from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest

from incident_replay.api import JsonApplication
from incident_replay.jsonio import canonical_json
from incident_replay.service import ReplayService


def post_body(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def api_event(source_id, sequence, clock, event_type, **content) -> dict:
    return {
        "source_id": source_id,
        "sequence": sequence,
        "source_clock": clock,
        "event_type": event_type,
        "content": content,
        "content_sha256": hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest(),
    }


class ReplayApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(ReplayService(self.connection))
        for user_id, role in (
            ("collector", "collector"), ("analyst", "analyst"),
            ("approver", "approver"), ("auditor", "auditor"),
        ):
            self.app.handle("POST", "/users", body=post_body(
                {"user_id": user_id, "display_name": user_id, "role": role}
            ))
        headers = {"X-Actor-Id": "analyst"}
        self.app.handle("POST", "/sources", headers, post_body(
            {"source_id": "s1", "domain": "control", "label": "总线"}
        ))
        self.app.handle("POST", "/calibrations", headers, post_body({
            "basis": "授时",
            "entries": [{
                "source_id": "s1", "drift_ppm": "0",
                "anchor_source": "2026-10-01T10:00:00Z",
                "anchor_reference": "2026-10-01T10:00:00Z",
            }],
        }))
        self.app.handle("POST", "/incidents", headers, post_body(
            {"incident_id": "I1", "title": "急停"}
        ))

    def tearDown(self) -> None:
        self.connection.close()

    def test_health_and_route_not_found(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        missing = self.app.handle("GET", "/nope")
        self.assertEqual(missing.status, 404)
        self.assertEqual(missing.body["error"]["code"], "route_not_found")

    def test_actor_required(self) -> None:
        response = self.app.handle("POST", "/incidents/I1/revisions", body=post_body(
            {"calibration_version": 1}
        ))
        self.assertEqual(response.status, 422)

    def test_full_flow_over_http(self) -> None:
        ingest = self.app.handle(
            "POST", "/incidents/I1/events",
            {"X-Actor-Id": "collector", "Idempotency-Key": "batch-1"},
            post_body({"events": [
                api_event("s1", 1, "2026-10-01T10:00:00.010Z", "estop_receipt",
                          device_id="r1", ticket_id="T1"),
                api_event("s1", 2, "2026-10-01T10:00:00.060Z", "note", x=2),
            ]}),
        )
        self.assertEqual(ingest.status, 200)
        self.assertEqual(ingest.body["inserted"], 2)

        revision = self.app.handle(
            "POST", "/incidents/I1/revisions", {"X-Actor-Id": "analyst"},
            post_body({"calibration_version": 1}),
        )
        self.assertEqual(revision.status, 201)
        self.assertEqual(revision.body["revision_no"], 1)

        got = self.app.handle("GET", "/incidents/I1/revisions/1", {"X-Actor-Id": "auditor"})
        self.assertEqual(got.status, 200)
        self.assertEqual(len(got.body["snapshot"]["arrival_order"]), 2)

        replay = self.app.handle("POST", "/incidents/I1/revisions/1/replay",
                                 {"X-Actor-Id": "auditor"})
        self.assertEqual(replay.status, 200)
        self.assertTrue(replay.body["timeline_matches"])

        # 单来源、无窗口冲突，可直接封存（无触发规则设备也允许空方案推导）。
        freeze = self.app.handle(
            "POST", "/incidents/I1/freeze", {"X-Actor-Id": "analyst"},
            post_body({
                "revision_no": 1, "trigger_record_ids": [1],
                "decision_basis": "calibrated_order", "rationale": "判定",
            }),
        )
        self.assertEqual(freeze.status, 201, freeze.body)

        # 冻结人确认被拒。
        forbidden = self.app.handle(
            "POST", "/incidents/I1/plan/confirm", {"X-Actor-Id": "analyst"}
        )
        self.assertEqual(forbidden.status, 403)

        confirmed = self.app.handle(
            "POST", "/incidents/I1/plan/confirm", {"X-Actor-Id": "approver"}
        )
        self.assertEqual(confirmed.status, 200)
        self.assertEqual(confirmed.body["status"], "confirmed")

        # 封存后直接写事件被拒。
        late_blocked = self.app.handle(
            "POST", "/incidents/I1/events",
            {"X-Actor-Id": "collector", "Idempotency-Key": "batch-2"},
            post_body({"events": [api_event("s1", 3, "2026-10-01T10:00:01Z", "x", y=3)]}),
        )
        self.assertEqual(late_blocked.status, 409)

        report = self.app.handle("GET", "/incidents/I1/report", {"X-Actor-Id": "auditor"})
        self.assertEqual(report.status, 200)
        self.assertEqual(len(report.body["revisions"]), 1)


if __name__ == "__main__":
    unittest.main()
