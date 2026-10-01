"""冻结时的影响推导。

从三类已登记证据确定性推导回退范围，不存在任何“默认覆盖”：

1. 时间线中实际出现的事件类型与异常；
2. 设备上的软件组合（部件/版本/摘要）；
3. 跨域票据点名的设备与部件、安全规则声明的触发条件。

输出严格排序并可随快照整体复算。
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

ACTION_KINDS = frozenset({
    "software_rollback",   # 软件回滚到指定版本
    "isolate_device",      # 设备隔离下电
    "hold_deployment",     # 暂停该部件的部署放行
    "disable_ai_model",    # 停用 AI 模型版本
    "quarantine_component",  # 隔离国产电子部件批次
})

# 异常码可作为规则的额外触发条件，以 anomaly: 前缀写在 event_kinds 中。
ANOMALY_TRIGGER_PREFIX = "anomaly:"


def _sorted_strings(values: Any) -> list[str]:
    return sorted({str(value) for value in values})


def derive_impact(
    timeline: Mapping[str, Any],
    manifest: Mapping[str, Any],
    tickets: Sequence[Mapping[str, Any]],
    rules: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """依据快照时刻的时间线、软件组合、票据和规则推导影响面。"""

    devices = tuple(manifest.get("devices", ()))
    entries = tuple(timeline.get("entries", ()))
    anomalies = tuple(timeline.get("anomalies", ()))

    present_kinds = {entry["kind"] for entry in entries}
    present_anomalies = {item["code"] for item in anomalies}
    event_devices = {
        entry.get("device_ref")
        for entry in entries
        if entry.get("device_ref")
    }

    open_tickets = tuple(ticket for ticket in tickets if ticket["status"] == "open")
    ticket_devices = {device for ticket in open_tickets for device in ticket["device_ids"]}
    ticket_components = {
        component for ticket in open_tickets for component in ticket["components"]
    }
    implicated = event_devices | ticket_devices

    deployment_index = {
        device["device_id"]: {item["component"]: item for item in device["deployments"]}
        for device in devices
    }

    fired_rule_ids: list[str] = []
    contributing_tickets: set[str] = set()
    action_index: dict[tuple[str, str, str], dict[str, Any]] = {}
    affected: dict[str, dict[str, Any]] = {}

    for rule in sorted(rules, key=lambda item: (item["priority"], item["rule_id"])):
        if not rule.get("active", True):
            continue
        triggers = tuple(rule["event_kinds"])
        kind_triggers = {trigger for trigger in triggers if not trigger.startswith(ANOMALY_TRIGGER_PREFIX)}
        anomaly_triggers = {
            trigger[len(ANOMALY_TRIGGER_PREFIX):]
            for trigger in triggers
            if trigger.startswith(ANOMALY_TRIGGER_PREFIX)
        }
        kind_hit = bool(kind_triggers & present_kinds)
        anomaly_hit = bool(anomaly_triggers & present_anomalies)
        if not kind_hit and not anomaly_hit:
            continue
        rule_components = set(rule["components"])
        for device in sorted(devices, key=lambda item: item["device_id"]):
            device_id = device["device_id"]
            deployed = deployment_index.get(device_id, {})
            matched_components = sorted(rule_components & set(deployed))
            device_implicated = device_id in implicated
            component_ticket_hit = bool(rule_components & ticket_components)
            if not matched_components or not (device_implicated or component_ticket_hit):
                continue
            evidence: list[str] = []
            if kind_hit and device_id in event_devices:
                evidence.append("event:" + ",".join(sorted(kind_triggers & present_kinds)))
            if anomaly_hit:
                evidence.append(
                    "anomaly:" + ",".join(sorted(anomaly_triggers & present_anomalies))
                )
            for ticket in open_tickets:
                if device_id in ticket["device_ids"] and (
                    set(ticket["components"]) & rule_components
                ):
                    evidence.append(f"ticket:{ticket['ticket_id']}")
                    contributing_tickets.add(ticket["ticket_id"])
            for ticket in open_tickets:
                if device_id in ticket["device_ids"] and device_id in event_devices:
                    contributing_tickets.add(ticket["ticket_id"])
            fired_rule_ids.append(rule["rule_id"])
            affected.setdefault(
                device_id,
                {
                    "device_id": device_id,
                    "kind": device["kind"],
                    "owner_team": device["owner_team"],
                    "matched_components": set(),
                    "evidence": set(),
                },
            )
            affected[device_id]["matched_components"].update(matched_components)
            affected[device_id]["evidence"].update(evidence)
            key = (device_id, rule["action_kind"], rule["rollback_target"])
            if key not in action_index:
                action_index[key] = {
                    "device_id": device_id,
                    "action_kind": rule["action_kind"],
                    "target": rule["rollback_target"],
                    "priority": rule["priority"],
                    "rule_ids": [],
                    "matched_components": set(),
                }
            action_index[key]["rule_ids"].append(rule["rule_id"])
            action_index[key]["matched_components"].update(matched_components)

    candidate_actions = sorted(
        action_index.values(),
        key=lambda item: (item["priority"], item["device_id"], item["action_kind"], item["target"]),
    )
    for ordinal, action in enumerate(candidate_actions, start=1):
        action["ordinal"] = ordinal
        action["rule_ids"] = sorted(set(action["rule_ids"]))
        action["matched_components"] = sorted(action["matched_components"])

    affected_devices = []
    for device_id in sorted(affected):
        item = affected[device_id]
        affected_devices.append(
            {
                "device_id": device_id,
                "kind": item["kind"],
                "owner_team": item["owner_team"],
                "matched_components": sorted(item["matched_components"]),
                "evidence": sorted(item["evidence"]),
            }
        )

    notify_roles = {
        role
        for rule in rules
        if rule["rule_id"] in set(fired_rule_ids)
        for role in rule["notify_roles"]
    }
    notify_teams = {item["owner_team"] for item in affected_devices}
    notify_contacts = {
        contact
        for device in devices
        if device["device_id"] in affected
        for contact in device.get("contacts", [])
    }
    ticket_domains = {
        ticket["domain"] for ticket in open_tickets if ticket["ticket_id"] in contributing_tickets
    }

    decision_basis = {
        "calibration_version": timeline.get("calibration_version"),
        "timeline_sha256": timeline.get("timeline_sha256"),
        "event_kinds": _sorted_strings(present_kinds),
        "anomaly_codes": _sorted_strings(present_anomalies),
        "fired_rule_ids": sorted(set(fired_rule_ids)),
        "contributing_ticket_ids": sorted(contributing_tickets),
        "implicated_device_ids": sorted(implicated),
    }
    return {
        "affected_devices": affected_devices,
        "candidate_actions": candidate_actions,
        "decision_basis": decision_basis,
        "notify_scope": {
            "roles": sorted(notify_roles),
            "teams": sorted(notify_teams),
            "contacts": sorted(notify_contacts),
            "ticket_domains": sorted(ticket_domains),
        },
    }
