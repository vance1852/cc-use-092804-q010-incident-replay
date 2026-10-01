"""现场异常回放服务的离线验收入口。

在临时 SQLite 数据库中复现一次急停争议：控制回执、AI 决策、部件告警
以人工拼接顺序到达，时钟经校准版本归一；封存后由另一名授权者批准回退，
迟到证据经复开形成新修订，旧结论原样保留。
"""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FrozenClock
from .service import ReplayService
from .storage import connect, inspect_schema


def _event(source_id, sequence, source_clock, kind, digest, device_ref=None):
    return {
        "source_id": source_id,
        "sequence": sequence,
        "source_clock": source_clock,
        "kind": kind,
        "content_digest": digest,
        "device_ref": device_ref,
        "payload": {},
    }


def run(workspace: Path) -> dict[str, object]:
    base = datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc)

    def iso(ms):
        return (base + _millis(ms)).isoformat().replace("+00:00", "Z")

    with tempfile.TemporaryDirectory(prefix="incident-replay-") as temporary:
        database = Path(temporary) / "incident.sqlite3"
        connection = connect(database)
        frozen = FrozenClock(base)
        try:
            service = ReplayService(connection, frozen)
            for user_id, name, role in (
                ("field-1", "现场工程师", "field_engineer"),
                ("inv-1", "调查负责人", "investigator"),
                ("safety-1", "安全授权人", "safety_officer"),
                ("dispatch-1", "通知调度员", "dispatcher"),
                ("auditor-1", "审计人员", "auditor"),
            ):
                service.create_user(user_id, name, role)

            service.create_incident("field-1", "INC-ESTOP-01", "1 号机急停触发原因争议", "20")

            for device_id, kind, team, contacts in (
                ("ctrl-node-1", "control_node", "control-team", ["ctrl-oncall@example"]),
                ("robot-arm-7", "manipulator", "control-team", ["arm-oncall@example"]),
                ("npu-unit-3", "ai_accelerator", "ai-team", ["ai-oncall@example"]),
            ):
                service.register_device("field-1", "INC-ESTOP-01", device_id, kind, team, contacts)

            service.upsert_deployment("field-1", "INC-ESTOP-01", "ctrl-node-1",
                                      "motion-controller", "3.2.0", "a" * 64)
            service.upsert_deployment("field-1", "INC-ESTOP-01", "robot-arm-7",
                                      "motion-controller", "3.2.0", "a" * 64)
            service.upsert_deployment("field-1", "INC-ESTOP-01", "robot-arm-7",
                                      "safety-firmware", "1.8.1", "b" * 64)
            service.upsert_deployment("field-1", "INC-ESTOP-01", "npu-unit-3",
                                      "vision-model", "5.0.0", "c" * 64)

            service.register_ticket("field-1", "INC-ESTOP-01", "T-CTRL-01", "control",
                                    "控制总线回执顺序异常",
                                    ["ctrl-node-1", "robot-arm-7"], ["motion-controller"])
            service.register_ticket("field-1", "INC-ESTOP-01", "T-AI-02", "ai_compute",
                                    "急停前 AI 决策延迟",
                                    ["npu-unit-3"], ["vision-model"])

            service.register_safety_rule("field-1", "INC-ESTOP-01", {
                "rule_id": "R-ESTOP-01",
                "title": "部件告警触发运动控制回滚",
                "event_kinds": ["component_alarm"],
                "components": ["motion-controller", "safety-firmware"],
                "action_kind": "software_rollback",
                "rollback_target": "motion-controller-3.1.4",
                "priority": 10,
                "notify_roles": ["safety_officer", "investigator"],
            })
            service.register_safety_rule("field-1", "INC-ESTOP-01", {
                "rule_id": "R-AI-02",
                "title": "AI 决策异常停用模型版本",
                "event_kinds": ["ai_decision"],
                "components": ["vision-model"],
                "action_kind": "disable_ai_model",
                "rollback_target": "vision-model-4.9.3",
                "priority": 20,
                "notify_roles": ["safety_officer"],
            })
            service.register_safety_rule("field-1", "INC-ESTOP-01", {
                "rule_id": "R-ORDER-03",
                "title": "时间顺序矛盾冻结放行",
                "event_kinds": ["anomaly:ordering_conflict"],
                "components": ["motion-controller"],
                "action_kind": "hold_deployment",
                "rollback_target": "motion-controller-release-gate",
                "priority": 30,
                "notify_roles": ["investigator", "auditor"],
            })

            # 校准版本 1：控制总线时钟无偏移；AI 网关锚点表明其时钟慢 120ms；
            # 部件网关整体快 300ms（权威时间 = 源时间 - 300ms）。
            service.add_calibration("inv-1", "INC-ESTOP-01", {
                "source_id": "ctrl-bus", "kind": "offset",
                "effective_at": iso(0), "offset_ms": "0", "basis": "总线 PTP 主时钟",
            })
            service.add_calibration("inv-1", "INC-ESTOP-01", {
                "source_id": "ai-gw", "kind": "anchor",
                "effective_at": iso(0), "source_at": iso(0),
                "reference_at": iso(120), "basis": "AI 网关 NTP 锚点对",
            })
            service.add_calibration("inv-1", "INC-ESTOP-01", {
                "source_id": "part-gw", "kind": "offset",
                "effective_at": iso(0), "offset_ms": "-300", "basis": "部件采集网关校时报告",
            })

            # 到达顺序：控制回执 -> AI 决策 -> 部件告警（人工拼接顺序）。
            # 校准后真实顺序相反：告警(40ms) < AI 决策(420ms) < 控制回执(500ms)。
            # ctrl-bus 序列号 1、3 制造缺口；同批到达保证接收间隔一致。
            batch_one = [
                _event("ctrl-bus", 1, iso(500), "control_receipt", "1" * 64, "ctrl-node-1"),
                _event("ai-gw", 1, iso(300), "ai_decision", "2" * 64, "npu-unit-3"),
                _event("part-gw", 1, iso(340), "component_alarm", "3" * 64, "robot-arm-7"),
                _event("ctrl-bus", 3, iso(520), "control_receipt", "4" * 64, "robot-arm-7"),
            ]
            first = service.ingest_events("field-1", "INC-ESTOP-01", "ingest-1", batch_one)

            # 重传：完全相同的事件再次送达，必须原样保留并标注重传而非覆盖。
            retransmit = service.ingest_events(
                "field-1", "INC-ESTOP-01", "ingest-2", [batch_one[0]]
            )

            # 相隔 200ms 后到达的同源续报：源时钟只走了 100ms，漂移残差 -100ms 超阈值。
            frozen.advance(milliseconds=200)
            drift_batch = [
                _event("part-gw", 2, iso(440), "component_alarm", "5" * 64, "robot-arm-7"),
            ]
            service.ingest_events("field-1", "INC-ESTOP-01", "ingest-3", drift_batch)

            timeline_a = service.current_timeline("INC-ESTOP-01")
            timeline_b = service.current_timeline("INC-ESTOP-01")
            if timeline_a != timeline_b:
                raise RuntimeError("时间线复算结果不确定")

            anomaly_codes = {item["code"] for item in timeline_a["anomalies"]}
            expected = {"duplicate_content", "sequence_gap", "clock_drift", "ordering_conflict"}
            if anomaly_codes != expected:
                raise RuntimeError(f"时间线异常标注不完整: {anomaly_codes}")
            first_seen: list[str] = []
            for entry in timeline_a["entries"]:
                if entry["source_id"] not in first_seen:
                    first_seen.append(entry["source_id"])
            if first_seen != ["part-gw", "ai-gw", "ctrl-bus"]:
                raise RuntimeError(f"校准排序与证据不符: {first_seen}")

            frozen_rev1 = service.freeze_revision(
                "inv-1", "INC-ESTOP-01", 0, "初版：以校准版本 1 复算急停前后顺序"
            )
            revision1 = frozen_rev1["revision"]
            impact = frozen_rev1["impact"]
            affected = {item["device_id"] for item in impact["affected_devices"]}
            if affected != {"ctrl-node-1", "robot-arm-7", "npu-unit-3"}:
                raise RuntimeError(f"受影响设备推导错误: {affected}")
            action_keys = {(a["device_id"], a["action_kind"]) for a in impact["candidate_actions"]}
            if ("robot-arm-7", "software_rollback") not in action_keys:
                raise RuntimeError("未推导出机械臂软件回退动作")
            if ("ctrl-node-1", "hold_deployment") not in action_keys:
                raise RuntimeError("顺序矛盾未推导出放行冻结动作")

            plan = service.propose_plan("inv-1", "INC-ESTOP-01", revision1, "按封存修订 1 的候选动作执行")

            # 提出者不能自批。
            try:
                service.review_plan("inv-1", plan["plan_id"], True, "自批")
            except Exception as exc:
                if type(exc).__name__ != "Forbidden":
                    raise
            else:
                raise RuntimeError("提出者自批未被拒绝")

            # 未批准前不能执行。
            try:
                service.update_action("safety-1", plan["plan_id"], plan["actions"][0]["action_id"],
                                      "in_progress", "提前执行")
            except Exception as exc:
                if type(exc).__name__ != "InvalidState":
                    raise
            else:
                raise RuntimeError("未批准计划被执行")

            service.review_plan("safety-1", plan["plan_id"], True, "安全负责人复核确认")
            first_action = plan["actions"][0]
            service.update_action("safety-1", plan["plan_id"], first_action["action_id"],
                                  "in_progress", "开始回滚")
            service.update_action("safety-1", plan["plan_id"], first_action["action_id"],
                                  "succeeded", "回滚完成并复测通过")
            progress = service.device_progress("INC-ESTOP-01")
            if progress["devices"][first_action["device_id"]]["count_succeeded"] != 1:
                raise RuntimeError("设备回退进度统计错误")

            notification = service.dispatch_notification(
                "dispatch-1", "INC-ESTOP-01", revision1, "secure-im"
            )

            # 封存后迟到证据不能直接写入。
            late_event = _event("part-gw", 1, iso(341), "component_alarm", "9" * 64, "robot-arm-7")
            try:
                service.ingest_events("field-1", "INC-ESTOP-01", "ingest-late", [late_event])
            except Exception as exc:
                if type(exc).__name__ != "InvalidState":
                    raise
            else:
                raise RuntimeError("封存结论被迟到证据直接改写")

            reopen = service.request_reopen("inv-1", "INC-ESTOP-01", "部件网关补传同序列号记录，摘要不同")
            service.review_reopen("safety-1", reopen["request_id"], True, "允许复算形成新修订")
            late_result = service.ingest_events(
                "field-1", "INC-ESTOP-01", "ingest-late", [late_event]
            )
            if late_result["conflict_count"] != 1:
                raise RuntimeError("迟到冲突证据未被标记")

            frozen_rev2 = service.freeze_revision(
                "inv-1", "INC-ESTOP-01", 1, "修订 2：纳入补传记录，冲突显式并列"
            )
            revision1_again = service.get_revision("INC-ESTOP-01", 1)
            if revision1_again["timeline_sha256"] != frozen_rev1["timeline_sha256"]:
                raise RuntimeError("已封存结论被改写")
            if frozen_rev2["revision"] != 2:
                raise RuntimeError("迟到证据未形成新修订版本")

            report = service.report("auditor-1", "INC-ESTOP-01")
            schema = inspect_schema(connection)
            result = {
                "status": "ok",
                "incident": "INC-ESTOP-01",
                "arrival_event_count": first["received"],
                "retransmit_marked": retransmit["retransmit_count"],
                "anomalies": sorted(anomaly_codes),
                "timeline_sha256_v1": frozen_rev1["timeline_sha256"],
                "timeline_sha256_v2": frozen_rev2["timeline_sha256"],
                "affected_devices": sorted(affected),
                "candidate_actions_v1": len(impact["candidate_actions"]),
                "plan_status": service.get_plan(plan["plan_id"])["status"],
                "progress_devices": sorted(progress["devices"]),
                "notification_recipients": notification["recipients"],
                "report_revisions": len(report["revisions"]),
                "audit_event_count": len(report["audit_events"]),
                "schema": schema,
            }
        finally:
            connection.close()
    if result["schema"]["missing_tables"] or result["schema"]["schema_version"] != "1":
        raise RuntimeError("SQLite 基础结构检查失败")
    return result


def _millis(value: int):
    from datetime import timedelta

    return timedelta(milliseconds=value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行现场异常回放服务的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
