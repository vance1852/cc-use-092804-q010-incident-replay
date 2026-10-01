from __future__ import annotations

import unittest

from incident_replay.impact import derive_plan


SNAPSHOT = {
    "arrival_order": [
        {"record_id": 1, "domain": "control", "event_type": "estop_receipt",
         "content": {"device_id": "robot-r1", "ticket_id": "T-1"}},
        {"record_id": 2, "domain": "component", "event_type": "overcurrent_alert",
         "content": {"device_id": "robot-r2"}},
    ],
}

COMBOS = [
    {"combo_id": "c-ctrl", "domain": "control", "components": ["motion-controller", "safety-plc"]},
    {"combo_id": "c-ai", "domain": "ai", "components": ["perception", "motion-controller"]},
]
DEVICES = [
    {"device_id": "robot-r1", "domain": "control", "combo_id": "c-ctrl"},
    {"device_id": "robot-r2", "domain": "control", "combo_id": "c-ctrl"},
    {"device_id": "ai-edge-1", "domain": "ai", "combo_id": "c-ai"},
]
TICKETS = [
    {"ticket_id": "T-1", "summary": "跨域控制器变更", "domains": ["control", "ai"],
     "combo_ids": ["c-ctrl", "c-ai"], "device_ids": ["robot-r1", "ai-edge-1"]},
]
RULES = [
    {"rule_id": "r-estop", "version": 1, "event_types": ["estop_receipt", "overcurrent_alert"],
     "domains": ["control", "component"], "components": ["motion-controller"],
     "action": "rollback", "notify_roles": ["approver", "safety"]},
    {"rule_id": "r-other", "version": 1, "event_types": ["disk_full"],
     "domains": ["ai"], "components": [], "action": "isolate", "notify_roles": ["ops"]},
]


class ImpactDerivationTests(unittest.TestCase):
    def test_devices_tickets_rules_and_candidates(self) -> None:
        plan = derive_plan(SNAPSHOT, [1, 2], COMBOS, DEVICES, TICKETS, RULES)
        by_id = {item["device_id"]: item for item in plan["devices"]}
        # T-1 覆盖 robot-r1/ai-edge-1；规则组件命中 r1/r2；ai-edge 由票据传播。
        self.assertEqual(set(by_id), {"robot-r1", "robot-r2", "ai-edge-1"})
        self.assertTrue(
            any("T-1" in reason for reason in by_id["ai-edge-1"]["reasons"])
        )
        r1_types = {action["type"] for action in by_id["robot-r1"]["candidate_actions"]}
        self.assertIn("rollback", r1_types)
        self.assertIn("rollback_ticket", r1_types)
        # 未命中的规则不产生通知。
        self.assertEqual(set(plan["notifications"]), {"approver", "safety"})
        self.assertEqual(plan["trigger_domains"], ["component", "control"])

    def test_deterministic_across_input_order(self) -> None:
        first = derive_plan(SNAPSHOT, [1, 2], COMBOS, DEVICES[::-1], TICKETS, RULES[::-1])
        second = derive_plan(SNAPSHOT, [1, 2], COMBOS, DEVICES, TICKETS, RULES)
        self.assertEqual(first["devices"], second["devices"])

    def test_unknown_trigger_record_rejected(self) -> None:
        with self.assertRaises(ValueError):
            derive_plan(SNAPSHOT, [99], COMBOS, DEVICES, TICKETS, RULES)

    def test_unregistered_named_device_kept_with_null_domain(self) -> None:
        snapshot = {
            "arrival_order": [
                {"record_id": 1, "domain": "control", "event_type": "estop_receipt",
                 "content": {"device_id": "ghost-device"}},
            ],
        }
        plan = derive_plan(snapshot, [1], COMBOS, [], [], RULES)
        self.assertEqual([item["device_id"] for item in plan["devices"]], ["ghost-device"])
        self.assertIsNone(plan["devices"][0]["domain"])
        self.assertEqual(
            plan["devices"][0]["reasons"], ["触发事件内容直接点名 device_id"]
        )


if __name__ == "__main__":
    unittest.main()
