from __future__ import annotations

import json
import sqlite3
import unittest

from incident_replay.api import JsonApplication
from incident_replay.service import ReplayService


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(ReplayService(self.connection))
        self._post("/users", {"user_id": "field", "display_name": "现场", "role": "field_engineer"})
        self._post("/users", {"user_id": "inv", "display_name": "调查", "role": "investigator"})
        self._post("/users", {"user_id": "safety", "display_name": "安全", "role": "safety_officer"})

    def tearDown(self) -> None:
        self.connection.close()

    def _post(self, path, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self.app.handle("POST", path, headers or {}, body)

    def _get(self, path, headers=None):
        return self.app.handle("GET", path, headers or {})

    def test_health(self) -> None:
        response = self._get("/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_actor_required(self) -> None:
        response = self._post("/incidents", {"incident_id": "X", "title": "t"})
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_full_http_flow(self) -> None:
        headers = {"X-Actor-Id": "field"}
        self.assertEqual(self._post("/incidents", {
            "incident_id": "INC-9", "title": "急停", "drift_threshold_ms": "10",
        }, headers).status, 201)
        events = {
            "events": [{
                "source_id": "s1", "sequence": 1,
                "source_clock": "2026-10-01T02:00:00Z",
                "kind": "control_receipt",
                "content_digest": "a" * 64,
                "payload": {},
            }]
        }
        response = self._post("/incidents/INC-9/events", events,
                              {"X-Actor-Id": "field", "Idempotency-Key": "k1"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["received"], 1)

        timeline = self._get("/incidents/INC-9/timeline", {"X-Actor-Id": "inv"})
        self.assertEqual(timeline.status, 200)
        self.assertEqual(timeline.body["event_count"], 1)

        freeze = self._post("/incidents/INC-9/freeze",
                            {"expected_revision": 0, "rationale": "结论"},
                            {"X-Actor-Id": "inv"})
        self.assertEqual(freeze.status, 201)
        revision = freeze.body["revision"]

        plan = self._post("/rollback-plans", {
            "incident_id": "INC-9", "revision": revision, "rationale": "回退",
        }, {"X-Actor-Id": "inv"})
        # 无候选动作 -> 409 invalid_state
        self.assertEqual(plan.status, 409)

        response = self._post("/incidents/INC-9/close", {}, {"X-Actor-Id": "safety"})
        # 无已批准动作，允许关闭
        self.assertEqual(response.status, 200)

    def test_error_shape(self) -> None:
        response = self._post("/users", {"user_id": "x", "display_name": "x", "role": "bad"})
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_route_not_found(self) -> None:
        response = self._get("/nope")
        self.assertEqual(response.status, 404)


if __name__ == "__main__":
    unittest.main()
