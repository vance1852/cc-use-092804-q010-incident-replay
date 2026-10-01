from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from incident_replay.clock import FrozenClock
from incident_replay.errors import Conflict, Forbidden, InvalidState
from incident_replay.service import ReplayService


def event(source, sequence, clock, digest, kind="component_alarm", device=None):
    return {
        "source_id": source,
        "sequence": sequence,
        "source_clock": clock,
        "kind": kind,
        "content_digest": digest,
        "device_ref": device,
        "payload": {},
    }


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc))
        self.service = ReplayService(self.connection, self.clock)
        for user_id, role in (
            ("field", "field_engineer"),
            ("inv", "investigator"),
            ("safety", "safety_officer"),
            ("dispatcher", "dispatcher"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.service.create_incident("field", "INC-1", "测试异常", "50")

    def tearDown(self) -> None:
        self.connection.close()

    def _freeze(self):
        self.service.ingest_events("field", "INC-1", "k1", [
            event("s1", 1, "2026-10-01T02:00:00Z", "a" * 64, device="dev-1"),
        ])
        return self.service.freeze_revision("inv", "INC-1", 0, "初版结论")

    def test_role_permissions(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.add_calibration("field", "INC-1", {
                "source_id": "s1", "kind": "offset",
                "effective_at": "2026-10-01T02:00:00Z", "offset_ms": "0", "basis": "x",
            })
        with self.assertRaises(Forbidden):
            self.service.freeze_revision("field", "INC-1", 0, "x")

    def test_idempotent_ingest(self) -> None:
        rows = [event("s1", 1, "2026-10-01T02:00:00Z", "a" * 64)]
        first = self.service.ingest_events("field", "INC-1", "key-1", rows)
        second = self.service.ingest_events("field", "INC-1", "key-1", rows)
        self.assertEqual(first, second)
        with self.assertRaises(Conflict):
            self.service.ingest_events("field", "INC-1", "key-1", [
                event("s1", 2, "2026-10-01T02:00:01Z", "b" * 64),
            ])

    def test_frozen_incident_rejects_late_evidence_until_reopen(self) -> None:
        frozen = self._freeze()
        with self.assertRaises(InvalidState):
            self.service.ingest_events("field", "INC-1", "k2", [
                event("s1", 2, "2026-10-01T02:00:01Z", "c" * 64),
            ])
        request = self.service.request_reopen("inv", "INC-1", "补传证据")
        # 申请人不能自批复开。
        with self.assertRaises(Forbidden):
            self.service.review_reopen("inv", request["request_id"], True, "自批")
        self.service.review_reopen("safety", request["request_id"], True, "同意")
        late = self.service.ingest_events("field", "INC-1", "k2", [
            event("s1", 2, "2026-10-01T02:00:01Z", "c" * 64),
        ])
        self.assertEqual(late["received"], 1)
        second = self.service.freeze_revision("inv", "INC-1", 1, "新修订")
        self.assertEqual(second["revision"], 2)
        # 旧封存结论原样保留。
        old = self.service.get_revision("INC-1", 1)
        self.assertEqual(old["timeline_sha256"], frozen["timeline_sha256"])
        self.assertNotEqual(second["timeline_sha256"], frozen["timeline_sha256"])

    def test_rejected_reopen_keeps_frozen_state(self) -> None:
        self._freeze()
        request = self.service.request_reopen("inv", "INC-1", "补传证据")
        self.service.review_reopen("safety", request["request_id"], False, "证据不成立")
        self.assertEqual(self.service.get_incident("INC-1")["state"], "frozen")
        with self.assertRaises(InvalidState):
            self.service.ingest_events("field", "INC-1", "k2", [
                event("s1", 2, "2026-10-01T02:00:01Z", "c" * 64),
            ])

    def _prepare_impact(self):
        self.service.register_device("field", "INC-1", "dev-1", "control_node", "team-a", ["oncall@x"])
        self.service.upsert_deployment("field", "INC-1", "dev-1",
                                       "motion-controller", "3.2.0", "a" * 64)
        self.service.register_ticket("field", "INC-1", "T-1", "control", "票据",
                                     ["dev-1"], ["motion-controller"])
        self.service.register_safety_rule("field", "INC-1", {
            "rule_id": "R-1", "title": "告警回滚", "event_kinds": ["component_alarm"],
            "components": ["motion-controller"], "action_kind": "software_rollback",
            "rollback_target": "3.1.0", "priority": 10, "notify_roles": ["safety_officer"],
        })

    def test_plan_requires_separation_of_duties_and_progress(self) -> None:
        self._prepare_impact()
        self.service.ingest_events("field", "INC-1", "k1", [
            event("s1", 1, "2026-10-01T02:00:00Z", "a" * 64, device="dev-1"),
        ])
        frozen = self.service.freeze_revision("inv", "INC-1", 0, "初版")
        plan = self.service.propose_plan("inv", "INC-1", frozen["revision"], "执行回退")
        with self.assertRaises(Forbidden):
            self.service.review_plan("inv", plan["plan_id"], True, "自批")
        with self.assertRaises(InvalidState):
            self.service.update_action(
                "safety", plan["plan_id"], plan["actions"][0]["action_id"], "in_progress", "提前"
            )
        self.service.review_plan("safety", plan["plan_id"], True, "确认")
        action_id = plan["actions"][0]["action_id"]
        self.service.update_action("safety", plan["plan_id"], action_id, "in_progress", "执行中")
        # 不能跳过必须的终态。
        with self.assertRaises(InvalidState):
            self.service.update_action("safety", plan["plan_id"], action_id, "pending", "回退")
        self.service.update_action("safety", plan["plan_id"], action_id, "succeeded", "完成")
        progress = self.service.device_progress("INC-1")
        self.assertEqual(progress["devices"]["dev-1"]["completed_fraction"], "1/1")
        self.assertTrue(progress["devices"]["dev-1"]["finished"])

    def test_impact_derivation_uses_manifest_and_rules(self) -> None:
        self._prepare_impact()
        self.service.ingest_events("field", "INC-1", "k1", [
            event("s1", 1, "2026-10-01T02:00:00Z", "a" * 64,
                  kind="component_alarm", device="dev-1"),
        ])
        frozen = self.service.freeze_revision("inv", "INC-1", 0, "初版")
        affected = frozen["impact"]["affected_devices"]
        self.assertEqual([item["device_id"] for item in affected], ["dev-1"])
        actions = frozen["impact"]["candidate_actions"]
        self.assertEqual(actions[0]["action_kind"], "software_rollback")
        self.assertEqual(actions[0]["target"], "3.1.0")
        self.assertEqual(frozen["impact"]["notify_scope"]["roles"], ["safety_officer"])

    def test_freeze_optimistic_revision(self) -> None:
        self.service.ingest_events("field", "INC-1", "k1", [
            event("s1", 1, "2026-10-01T02:00:00Z", "a" * 64),
        ])
        with self.assertRaises(Conflict):
            self.service.freeze_revision("inv", "INC-1", 5, "错误版本")


if __name__ == "__main__":
    unittest.main()
