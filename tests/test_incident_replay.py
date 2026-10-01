from __future__ import annotations

import hashlib
import sqlite3
import unittest
from datetime import datetime, timezone
from decimal import Decimal

from incident_replay.clock import FrozenClock
from incident_replay.errors import Conflict, Forbidden, InvalidState, ValidationFailed
from incident_replay.jsonio import canonical_json
from incident_replay.models import SourceCalibration
from incident_replay.service import ReplayService
from incident_replay.timeline import build_timeline, convert_reference


def digest(content: dict) -> str:
    return hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()


def make_event(source_id, sequence, source_clock, event_type="evt", record_id=None, rank=None, **content):
    return {
        "record_id": record_id if record_id is not None else sequence,
        "source_id": source_id,
        "sequence": sequence,
        "source_clock": source_clock,
        "event_type": event_type,
        "content": content or {"v": sequence},
        "content_sha256": digest(content or {"v": sequence}),
        "arrival_rank": rank if rank is not None else sequence,
    }


class TimelineEngineTests(unittest.TestCase):
    def calibration(self, source_id, drift_ppm="0", source="2026-10-01T10:00:00Z",
                    reference="2026-10-01T10:00:00Z"):
        return SourceCalibration(
            source_id=source_id, drift_ppm=Decimal(drift_ppm),
            anchor_source=source, anchor_reference=reference,
        )

    def test_offset_and_drift_conversion(self) -> None:
        calib = self.calibration("s", drift_ppm="100", reference="2026-10-01T10:00:01Z")
        converted = convert_reference("2026-10-01T10:00:11Z", calib)
        # 锚点偏移 1s，经过 11s（含 100ppm 漂移）=> 1 + 11.0011 = 12.0011s
        self.assertEqual(converted, "2026-10-01T10:00:12.001100Z")

    def test_arrival_order_preserved_and_calibrated_order_deterministic(self) -> None:
        calibrations = {"a": self.calibration("a"), "b": self.calibration("b")}
        records = [
            make_event("a", 1, "2026-10-01T10:00:00.010Z", rank=2),
            make_event("b", 1, "2026-10-01T10:00:00.000Z", rank=1),
        ]
        t1 = build_timeline(records, calibrations, 1)
        shuffled = [records[1], records[0]]
        t2 = build_timeline(shuffled, calibrations, 1)
        self.assertEqual(
            [event.source_id for event in t1.arrival_order],
            [event.source_id for event in t2.arrival_order],
        )
        self.assertEqual([event.source_id for event in t1.arrival_order], ["b", "a"])
        self.assertEqual([event.source_id for event in t1.calibrated_order], ["b", "a"])
        self.assertEqual(t1.timeline_sha256, t2.timeline_sha256)

    def test_conflict_annotation_when_ordering_reversed(self) -> None:
        calibrations = {"a": self.calibration("a"), "b": self.calibration("b")}
        records = [
            # b 先到，但校准时间比 a 晚 2ms —— 两种顺序相反。
            make_event("b", 1, "2026-10-01T10:00:00.002Z", rank=1),
            make_event("a", 1, "2026-10-01T10:00:00.000Z", rank=2),
        ]
        timeline = build_timeline(records, calibrations, 1, conflict_window_ms=5)
        conflicts = [item for item in timeline.annotations if item.kind == "conflict"]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].severity, "critical")

    def test_gap_and_uncalibrated_annotations(self) -> None:
        timeline = build_timeline(
            [make_event("a", 1, "2026-10-01T10:00:00Z", rank=1),
             make_event("a", 3, "2026-10-01T10:00:01Z", rank=2)],
            {}, 0,
        )
        kinds = {item.kind: item for item in timeline.annotations}
        self.assertIn("gap", kinds)
        self.assertIn("uncalibrated_source", kinds)
        self.assertTrue(all(event.calibration_status == "uncalibrated" for event in timeline.arrival_order))

    def test_drift_annotation_threshold(self) -> None:
        timeline = build_timeline(
            [make_event("a", 1, "2026-10-01T10:00:00Z")],
            {"a": self.calibration("a", drift_ppm="150")}, 1,
        )
        self.assertTrue(any(item.kind == "drift" for item in timeline.annotations))


def api_event(source_id, sequence, clock, event_type, **content) -> dict:
    return {
        "source_id": source_id,
        "sequence": sequence,
        "source_clock": clock,
        "event_type": event_type,
        "content": content,
        "content_sha256": digest(content),
    }


class ReplayServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc))
        self.service = ReplayService(self.connection, self.clock)
        for user_id, role in (
            ("collector", "collector"),
            ("analyst", "analyst"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.service.register_source("analyst", "src-ctrl", "control", "控制总线")
        self.service.register_source("analyst", "src-ai", "ai", "AI 节点")
        self.service.publish_calibration("analyst", "授时记录", [
            {"source_id": "src-ctrl", "drift_ppm": "0",
             "anchor_source": "2026-10-01T10:00:00Z", "anchor_reference": "2026-10-01T10:00:00Z"},
            {"source_id": "src-ai", "drift_ppm": "0",
             "anchor_source": "2026-10-01T10:00:00Z", "anchor_reference": "2026-10-01T10:00:00Z"},
        ])
        self.service.register_combo("analyst", "combo-1", "control", ["motion-controller"])
        self.service.register_device("analyst", "robot-1", "control", "combo-1")
        self.service.register_ticket(
            "analyst", "T-1", "跨域变更", ["control", "ai"], ["combo-1"], ["robot-1"]
        )
        self.service.register_safety_rule("analyst", {
            "rule_id": "r1", "version": 1,
            "event_types": ["estop_receipt"],
            "domains": ["control"],
            "components": ["motion-controller"],
            "action": "rollback",
            "notify_roles": ["approver", "safety"],
        })
        self.service.create_incident("analyst", "INC-1", "急停争议")
        self.service.ingest_events("collector", "INC-1", "k1", [
            api_event("src-ctrl", 1, "2026-10-01T10:00:00.010Z", "estop_receipt",
                      ticket_id="T-1", device_id="robot-1"),
            # 与控制回执相隔 40ms，不落入冲突窗口，常规流程无需确认冲突。
            api_event("src-ai", 1, "2026-10-01T10:00:00.050Z", "motion_decision", decision="stop"),
        ])

    def tearDown(self) -> None:
        self.connection.close()

    def test_duplicate_sequence_conflict_and_idempotent_replay(self) -> None:
        duplicate = api_event("src-ctrl", 1, "2026-10-01T10:00:00.010Z", "estop_receipt", x=1)
        # 内容不同也不能覆盖；(案卷,来源,序列号) 唯一。
        duplicate["content_sha256"] = digest({"x": 1})
        with self.assertRaises(Conflict):
            self.service.ingest_events("collector", "INC-1", "k2", [duplicate])
        again = self.service.ingest_events("collector", "INC-1", "k1", [
            api_event("src-ctrl", 1, "2026-10-01T10:00:00.010Z", "estop_receipt",
                      ticket_id="T-1", device_id="robot-1"),
            api_event("src-ai", 1, "2026-10-01T10:00:00.012Z", "motion_decision", decision="stop"),
        ])
        self.assertEqual(again["inserted"], 2)

    def test_content_digest_mismatch_rejected(self) -> None:
        bad = api_event("src-ctrl", 9, "2026-10-01T10:00:01Z", "estop_receipt", x=1)
        bad["content_sha256"] = "a" * 64
        with self.assertRaises(ValidationFailed):
            self.service.ingest_events("collector", "INC-1", "k3", [bad])

    def test_freeze_and_two_person_confirmation(self) -> None:
        revision = self.service.build_revision("analyst", "INC-1", 1)
        self.assertEqual(revision["revision_no"], 1)
        plan = self.service.freeze_conclusion(
            "analyst", "INC-1", 1, [1], "calibrated_order", "按校准时间判定",
        )
        self.assertEqual([d["device_id"] for d in plan["devices"]], ["robot-1"])
        with self.assertRaises(Forbidden):
            self.service.confirm_plan("analyst", "INC-1")
        self.service.confirm_plan("approver", "INC-1")
        action = plan["devices"][0]["candidate_actions"][0]
        executed = self.service.execute_device_action(
            "approver", "INC-1", "robot-1", action, "完成"
        )
        self.assertEqual(executed["progress"]["succeeded"], 1)
        self.assertEqual(executed["status"], "completed")

    def test_cannot_execute_before_confirmation(self) -> None:
        self.service.build_revision("analyst", "INC-1", 1)
        plan = self.service.freeze_conclusion(
            "analyst", "INC-1", 1, [1], "arrival_order", "依据到达顺序"
        )
        with self.assertRaises(InvalidState):
            self.service.execute_device_action(
                "approver", "INC-1", "robot-1", plan["devices"][0]["candidate_actions"][0], "x"
            )

    def test_critical_annotation_must_be_acknowledged_to_freeze(self) -> None:
        # 独立案卷：两来源事件相隔 2ms 且到达顺序与校准顺序相反。
        self.service.create_incident("analyst", "INC-2", "冲突案卷")
        self.service.ingest_events("collector", "INC-2", "kc", [
            api_event("src-ctrl", 1, "2026-10-01T10:00:00.002Z", "estop_receipt",
                      ticket_id="T-1", device_id="robot-1"),
            api_event("src-ai", 1, "2026-10-01T10:00:00.000Z", "motion_decision", decision="stop"),
        ])
        self.service.build_revision("analyst", "INC-2", 1)
        snapshot = self.service.get_revision("INC-2", 1)["snapshot"]
        trigger_ids = [item["record_id"] for item in snapshot["arrival_order"]]
        with self.assertRaises(InvalidState):
            self.service.freeze_conclusion(
                "analyst", "INC-2", 1, trigger_ids, "arrival_order", "未确认冲突"
            )
        # 显式确认冲突后允许封存。
        plan = self.service.freeze_conclusion(
            "analyst", "INC-2", 1, trigger_ids, "arrival_order", "已研判",
            conflict_acknowledged=True,
        )
        self.assertEqual(plan["status"], "proposed")

    def test_late_evidence_reopen_flow_preserves_old_conclusion(self) -> None:
        self.service.build_revision("analyst", "INC-1", 1)
        self.service.freeze_conclusion(
            "analyst", "INC-1", 1, [1], "calibrated_order", "初版结论",
            conflict_acknowledged=True,
        )
        with self.assertRaises(InvalidState):
            self.service.ingest_events("collector", "INC-1", "k4", [
                api_event("src-ctrl", 2, "2026-10-01T10:00:01Z", "note", x=2)
            ])
        request = self.service.submit_late_evidence("collector", "INC-1", "证据迟到", [
            api_event("src-ctrl", 2, "2026-10-01T10:00:01Z", "note", x=2)
        ])
        # 审批人不能是提交人本人；collector 也无审批权。
        with self.assertRaises(Forbidden):
            self.service.review_reopen("collector", request["request_id"], True, "n")
        reviewed = self.service.review_reopen("analyst", request["request_id"], True, "同意复开")
        self.assertEqual(reviewed["status"], "approved")
        revision2 = self.service.build_revision("analyst", "INC-1", 1)
        self.assertEqual(revision2["revision_no"], 2)
        self.service.freeze_conclusion(
            "analyst", "INC-1", 2, [1], "calibrated_order", "二版结论",
            conflict_acknowledged=True,
        )
        conclusions = self.service.get_conclusion("INC-1")
        self.assertEqual(
            [item["rationale"] for item in conclusions["conclusions"]],
            ["初版结论", "二版结论"],
        )

    def test_rejected_late_evidence_does_not_change_timeline(self) -> None:
        revision1 = self.service.build_revision("analyst", "INC-1", 1)
        digest_before = revision1["timeline_sha256"]
        self.service.freeze_conclusion(
            "analyst", "INC-1", 1, [1], "calibrated_order", "初版",
            conflict_acknowledged=True,
        )
        request = self.service.submit_late_evidence("collector", "INC-1", "存疑证据", [
            api_event("src-ai", 2, "2026-10-01T10:00:02Z", "note", x=3)
        ])
        self.service.review_reopen("analyst", request["request_id"], False, "来源不可信")
        incident = self.service.get_incident("INC-1")
        self.assertEqual(incident["state"], "sealed")
        # 旧记录原封不动。
        replay = self.service.replay_revision("INC-1", 1)
        self.assertEqual(replay["stored_timeline_sha256"], digest_before)
        self.assertTrue(replay["timeline_matches"])

    def test_replay_recomputes_identical_timeline(self) -> None:
        self.service.build_revision("analyst", "INC-1", 1)
        replay = self.service.replay_revision("INC-1", 1)
        self.assertTrue(replay["timeline_matches"])
        self.assertTrue(replay["snapshot_untampered"])

    def test_notification_scope_comes_from_rules(self) -> None:
        self.service.build_revision("analyst", "INC-1", 1)
        plan = self.service.freeze_conclusion(
            "analyst", "INC-1", 1, [1], "calibrated_order", "结论",
            conflict_acknowledged=True,
        )
        roles = {item["role"] for item in plan["notifications"]}
        self.assertEqual(roles, {"approver", "safety"})
        with self.assertRaises(InvalidState):
            self.service.mark_notified("approver", "INC-1", "nonexistent-role")
        self.service.confirm_plan("approver", "INC-1")
        self.service.mark_notified("approver", "INC-1", "safety")

    def test_role_permissions(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.build_revision("collector", "INC-1", 1)
        with self.assertRaises(Forbidden):
            self.service.freeze_conclusion(
                "approver", "INC-1", 1, [1], "arrival_order", "审批人不能封存"
            )
        with self.assertRaises(Forbidden):
            self.service.register_source("collector", "x", "control", "x")
        with self.assertRaises(Forbidden):
            self.service.confirm_plan("analyst", "INC-1")
        self.service.report("auditor", "INC-1")


if __name__ == "__main__":
    unittest.main()
