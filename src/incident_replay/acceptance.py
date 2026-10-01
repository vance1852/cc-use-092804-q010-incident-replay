"""现场异常回放与安全回退完整流程的离线验收入口。"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from .errors import Forbidden, InvalidState, ValidationFailed
from .jsonio import canonical_json
from .service import ReplayService
from .storage import connect, inspect_schema


def event(source_id: str, sequence: int, source_clock: str, event_type: str, **content: object) -> dict[str, object]:
    body = dict(content)
    digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    return {
        "source_id": source_id,
        "sequence": sequence,
        "source_clock": source_clock,
        "event_type": event_type,
        "content": body,
        "content_sha256": digest,
    }


def run(workspace: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="incident-replay-") as temporary:
        database = Path(temporary) / "incident.sqlite3"
        connection = connect(database)
        try:
            service = ReplayService(connection)

            # 用户：采集员、调查负责人（分析）、另一名授权者（审批）、审计。
            service.create_user("collector-1", "现场采集员", "collector")
            service.create_user("analyst-1", "调查负责人", "analyst")
            service.create_user("approver-1", "回退授权者", "approver")
            service.create_user("auditor-1", "安全审计员", "auditor")

            # 三个域的来源时钟；部件时钟存在 150ppm 漂移。
            service.register_source("analyst-1", "ctrl-bus", "control", "实时控制总线")
            service.register_source("analyst-1", "ai-node", "ai", "AI 决策节点")
            service.register_source("analyst-1", "comp-mon", "component", "国产部件监测")
            service.publish_calibration("analyst-1", "试前联合授时记录", [
                {
                    "source_id": "ctrl-bus", "drift_ppm": "0",
                    "anchor_source": "2026-10-01T10:00:00Z",
                    "anchor_reference": "2026-10-01T10:00:00Z",
                },
                {
                    "source_id": "ai-node", "drift_ppm": "0",
                    "anchor_source": "2026-10-01T10:00:00Z",
                    "anchor_reference": "2026-10-01T10:00:00Z",
                },
                {
                    "source_id": "comp-mon", "drift_ppm": "150",
                    "anchor_source": "2026-10-01T10:00:00Z",
                    "anchor_reference": "2026-10-01T10:00:00Z",
                },
            ])

            # 冻结时刻的现场主数据：软件组合、设备、跨域票据、安全规则。
            service.register_combo("analyst-1", "combo-ctrl-7", "control", ["motion-controller", "safety-plc"])
            service.register_combo("analyst-1", "combo-ai-3", "ai", ["perception-model", "motion-controller"])
            service.register_device("analyst-1", "robot-r1", "control", "combo-ctrl-7")
            service.register_device("analyst-1", "robot-r2", "control", "combo-ctrl-7")
            service.register_device("analyst-1", "ai-edge-1", "ai", "combo-ai-3")
            service.register_ticket(
                "analyst-1", "XDEV-22", "跨域运动控制器联合变更",
                ["control", "ai"], ["combo-ctrl-7", "combo-ai-3"], ["robot-r1", "ai-edge-1"],
            )
            service.register_safety_rule("analyst-1", {
                "rule_id": "rule-estop",
                "version": 1,
                "event_types": ["estop_receipt", "overcurrent_alert"],
                "domains": ["control", "component"],
                "components": ["motion-controller"],
                "action": "rollback",
                "notify_roles": ["approver", "safety"],
            })

            service.create_incident("analyst-1", "INC-20261001-01", "3 号机急停触发原因争议")

            # 人工拼接后的到达顺序：控制回执最先、部件告警其次、AI 决策最后；
            # 但校准时间显示三者挤在 2ms 内，AI 决策反而最早。
            service.ingest_events("collector-1", "INC-20261001-01", "arrival-batch-1", [
                event(
                    "ctrl-bus", 1, "2026-10-01T10:00:00.012Z", "estop_receipt",
                    ticket_id="XDEV-22", device_id="robot-r1", switch="hardware_chain",
                ),
                event(
                    "comp-mon", 1, "2026-10-01T10:00:00.011Z", "overcurrent_alert",
                    device_id="robot-r2", current_a="42.7",
                ),
                event(
                    "ai-node", 1, "2026-10-01T10:00:00.010Z", "motion_decision",
                    decision="slowdown", confidence="0.83",
                ),
                # ai-node 序列号 2 缺失，制造显式缺口（它将作为迟到证据补入）。
                event(
                    "ai-node", 3, "2026-10-01T10:00:00.040Z", "motion_decision",
                    decision="full_stop", confidence="0.96",
                ),
            ])

            revision1 = service.build_revision("analyst-1", "INC-20261001-01", 1)
            snapshot1 = revision1["snapshot"]
            arrival_types = [item["event_type"] for item in snapshot1["arrival_order"]]
            calibrated_types = [item["event_type"] for item in snapshot1["calibrated_order"]]
            assert arrival_types == ["estop_receipt", "overcurrent_alert", "motion_decision", "motion_decision"]
            assert calibrated_types[0] == "motion_decision", calibrated_types
            kinds1 = sorted({item["kind"] for item in snapshot1["annotations"]})
            assert {"conflict", "gap", "drift"} <= set(kinds1), kinds1
            critical1 = [item for item in snapshot1["annotations"] if item["severity"] == "critical"]
            assert critical1, "必须标出严重冲突/缺口"

            # 封存后直接写入必须被拒绝。
            plan1 = service.freeze_conclusion(
                "analyst-1", "INC-20261001-01", 1,
                trigger_record_ids=[1, 2],
                decision_basis="calibrated_order",
                rationale="校准时间显示 AI 减速决策早于急停回执 2ms，结合 XDEV-22 变更判断触发源为跨域运动控制器",
                conflict_acknowledged=True,
            )
            assert {item["device_id"] for item in plan1["devices"]} == {"robot-r1", "robot-r2", "ai-edge-1"}
            assert plan1["status"] == "proposed"
            sealed_write_blocked = False
            try:
                service.ingest_events(
                    "collector-1", "INC-20261001-01", "arrival-batch-x",
                    [event("ctrl-bus", 2, "2026-10-01T10:00:00.050Z", "note", x=1)],
                )
            except InvalidState:
                sealed_write_blocked = True
            assert sealed_write_blocked

            # 冻结人不能自己确认，必须另一名授权者。
            try:
                service.confirm_plan("analyst-1", "INC-20261001-01")
            except Forbidden:
                pass
            else:
                raise AssertionError("冻结人不应能确认自己的方案")
            service.confirm_plan("approver-1", "INC-20261001-01")

            # 未经推导的临时动作必须被拒绝。
            bogus_action = {
                "type": "shutdown", "rule_id": None, "rule_version": None,
                "ticket_id": None, "description": "现场临时编造",
            }
            try:
                service.execute_device_action(
                    "approver-1", "INC-20261001-01", "robot-r1", bogus_action, "x"
                )
            except ValidationFailed:
                pass
            else:
                raise AssertionError("非候选动作不应被执行")

            # 逐设备执行推导产生的候选动作。
            for device in plan1["devices"]:
                action = device["candidate_actions"][0]
                service.execute_device_action(
                    "approver-1", "INC-20261001-01", device["device_id"], action, "回退完成并复测正常"
                )
            progress = service.get_plan("INC-20261001-01")
            assert progress["status"] == "completed", progress["status"]
            assert progress["progress"]["succeeded"] == 3
            service.mark_notified("approver-1", "INC-20261001-01", "approver")
            service.mark_notified("approver-1", "INC-20261001-01", "safety")

            # 复算事件顺序：与封存快照一致且快照未被篡改。
            replay1 = service.replay_revision("INC-20261001-01", 1)
            assert replay1["timeline_matches"] and replay1["snapshot_untampered"]

            # 迟到证据：ai-node 缺失的序列号 2 在封存后找回，只能申请复开。
            late = service.submit_late_evidence(
                "collector-1", "INC-20261001-01", "日志网关缓冲溢出，序列号 2 延迟 40 分钟找回",
                [event(
                    "ai-node", 2, "2026-10-01T10:00:00.011Z", "motion_decision",
                    decision="brake_precheck", confidence="0.71",
                )],
            )
            review = service.review_reopen("analyst-1", late["request_id"], True, "证据链完整，批准复开")
            assert review["status"] == "approved"

            revision2 = service.build_revision("analyst-1", "INC-20261001-01", 1)
            kinds2 = {item["kind"] for item in revision2["snapshot"]["annotations"]}
            assert "gap" not in kinds2, "缺口补齐后不应再标 gap"
            assert revision2["revision_no"] == 2
            service.freeze_conclusion(
                "analyst-1", "INC-20261001-01", 2,
                trigger_record_ids=[1, 2],
                decision_basis="calibrated_order",
                rationale="新证据显示制动预检与部件过流同时发生，维持跨域控制器触发判断，回退范围不变",
                conflict_acknowledged=True,
            )
            service.confirm_plan("approver-1", "INC-20261001-01")

            # 旧封存结论原样保留，新版本只是追加。
            conclusions = service.get_conclusion("INC-20261001-01")
            assert [item["revision_no"] for item in conclusions["conclusions"]] == [1, 2]
            assert conclusions["conclusions"][0]["rationale"].startswith("校准时间显示")

            report = service.report("auditor-1", "INC-20261001-01")
            assert len(report["revisions"]) == 2
            assert report["plans"][0]["devices"][0]["exec_status"] == "succeeded"
            assert {item["status"] for item in report["reopen_requests"]} == {"approved"}
            notified = {
                (item["role"], item["status"])
                for plan in report["plans"] if plan["revision_no"] == 1
                for item in plan["notifications"]
            }
            assert notified == {("approver", "notified"), ("safety", "notified")}
            replay2 = service.replay_revision("INC-20261001-01", 2)
            assert replay2["timeline_matches"] and replay2["snapshot_untampered"]
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "1":
        raise RuntimeError("SQLite 基础结构检查失败")
    return {
        "status": "ok",
        "incident_id": "INC-20261001-01",
        "arrival_order": arrival_types,
        "calibrated_order": calibrated_types,
        "annotations_v1": sorted(kinds1),
        "affected_devices": sorted(item["device_id"] for item in plan1["devices"]),
        "revisions": [item["revision_no"] for item in report["revisions"]],
        "conclusions_preserved": [item["revision_no"] for item in conclusions["conclusions"]],
        "reopen_statuses": [item["status"] for item in report["reopen_requests"]],
        "rollback_progress_v1": report["plans"][0]["status"],
        "replay_v1_matches": replay1["timeline_matches"],
        "replay_v2_matches": replay2["timeline_matches"],
        "audit_event_count": len(report["events"]),
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行现场异常回放服务的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
