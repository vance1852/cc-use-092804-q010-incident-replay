"""冻结时的影响面与候选回退动作推导（纯函数，便于复算）。

所有输入均为冻结时刻的快照主数据，推导结果可解释、可复算：
每台受影响设备都附带原因链（触发记录、跨域票据、安全规则、软件组件）。
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def _as_text_set(value: object) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(str(item) for item in value)


def _candidate_key(action: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(action.get("type", "")),
        str(action.get("rule_id", "")),
        str(action.get("ticket_id", "")),
    )


def derive_plan(
    timeline_snapshot: Mapping[str, Any],
    trigger_record_ids: Sequence[int],
    combos: Sequence[Mapping[str, Any]],
    devices: Sequence[Mapping[str, Any]],
    tickets: Sequence[Mapping[str, Any]],
    rules: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """根据时间线快照与冻结时刻主数据推导回退方案。

    输出：{"devices": [...], "notifications": {role: [reasons]}, "matched_rules": [...]}。
    """

    trigger_ids = frozenset(int(value) for value in trigger_record_ids)
    events = [item for item in timeline_snapshot["arrival_order"] if int(item["record_id"]) in trigger_ids]
    event_by_id = {int(item["record_id"]): item for item in timeline_snapshot["arrival_order"]}
    unknown = sorted(trigger_ids - set(event_by_id))
    if unknown:
        raise ValueError(f"触发记录不存在于本版本: {unknown}")

    trigger_domains = frozenset(str(item["domain"]) for item in events)
    trigger_types = frozenset(str(item["event_type"]) for item in events)

    # 第一步：匹配安全规则（事件类型 + 域 + 软件组件）。
    combo_by_id = {str(item["combo_id"]): item for item in combos}
    matched: list[dict[str, Any]] = []
    for rule in rules:
        rule_types = _as_text_set(rule["event_types"])
        if not rule_types & trigger_types:
            continue
        rule_domains = _as_text_set(rule["domains"]) or trigger_domains
        if not rule_domains & trigger_domains:
            continue
        matched.append({
            "rule_id": str(rule["rule_id"]),
            "version": int(rule["version"]),
            "domains": sorted(rule_domains),
            "components": sorted(_as_text_set(rule["components"])),
            "action": str(rule["action"]),
            "notify_roles": sorted(_as_text_set(rule["notify_roles"])),
        })

    # 第二步：通过触发事件内容与跨域票据确定设备种子集合。
    reasons: dict[str, list[str]] = {}
    device_tickets: dict[str, list[str]] = {}
    matched_by_key = {(item["rule_id"], item["version"]): item for item in matched}

    named_ticket_ids: set[str] = set()
    named_device_ids: set[str] = set()
    for item in events:
        content = item.get("content") or {}
        if isinstance(content, Mapping) and content.get("ticket_id"):
            named_ticket_ids.add(str(content["ticket_id"]))
        if isinstance(content, Mapping) and content.get("device_id"):
            named_device_ids.add(str(content["device_id"]))

    for ticket in tickets:
        ticket_id = str(ticket["ticket_id"])
        ticket_domains = _as_text_set(ticket["domains"])
        ticket_devices = _as_text_set(ticket["device_ids"])
        linked = ticket_id in named_ticket_ids or bool(ticket_domains & trigger_domains)
        if not linked:
            continue
        for device_id in ticket_devices:
            reasons.setdefault(device_id, []).append(
                f"ticket:{ticket_id} 跨域票据覆盖（域 {sorted(ticket_domains)}）"
            )
            device_tickets.setdefault(device_id, []).append(ticket_id)
    for device_id in named_device_ids:
        reasons.setdefault(device_id, []).append("触发事件内容直接点名 device_id")

    # 第三步：组件传播——运行了命中规则组件组合的设备同样受影响。
    registered = {str(item["device_id"]): item for item in devices}
    for item in matched:
        components = frozenset(item["components"])
        for device in devices:
            device_id = str(device["device_id"])
            if item["domains"] and str(device["domain"]) not in item["domains"]:
                continue
            combo = combo_by_id.get(str(device.get("combo_id") or ""))
            if combo is None:
                continue
            combo_components = _as_text_set(combo.get("components"))
            hits = sorted(components & combo_components)
            if components and not hits:
                continue
            reason = (
                f"rule:{item['rule_id']}v{item['version']} 命中组件 {hits}"
                if hits else
                f"rule:{item['rule_id']}v{item['version']} 域内全部组合"
            )
            reasons.setdefault(device_id, []).append(reason)

    # 第四步：为每台受影响设备生成确定性的候选动作集合。
    affected_devices: list[dict[str, Any]] = []
    for device_id in sorted(reasons):
        device = registered.get(device_id)
        candidate_map: dict[tuple[str, str, str], dict[str, Any]] = {}
        device_reasons = reasons[device_id]
        for item in matched:
            applies = any(
                f"rule:{item['rule_id']}v{item['version']}" in reason for reason in device_reasons
            )
            if not applies and (device is None or str(device["domain"]) not in item["domains"]):
                continue
            action = {
                "type": item["action"],
                "rule_id": item["rule_id"],
                "rule_version": item["version"],
                "ticket_id": None,
                "description": (
                    f"按安全规则 {item['rule_id']}v{item['version']} 执行 {item['action']}"
                ),
            }
            candidate_map[_candidate_key(action)] = action
        for ticket_id in sorted(device_tickets.get(device_id, [])):
            action = {
                "type": "rollback_ticket",
                "rule_id": None,
                "rule_version": None,
                "ticket_id": ticket_id,
                "description": f"按跨域票据 {ticket_id} 回退该设备的软件组合变更",
            }
            candidate_map[_candidate_key(action)] = action
        affected_devices.append({
            "device_id": device_id,
            "domain": None if device is None else str(device["domain"]),
            "current_combo_id": None if device is None else device.get("combo_id"),
            "reasons": sorted(set(device_reasons)),
            "candidate_actions": [candidate_map[key] for key in sorted(candidate_map)],
        })

    notifications: dict[str, list[str]] = {}
    for item in matched:
        for role in item["notify_roles"]:
            notifications.setdefault(role, []).append(
                f"rule:{item['rule_id']}v{item['version']}"
            )

    return {
        "devices": affected_devices,
        "notifications": {role: sorted(set(values)) for role, values in sorted(notifications.items())},
        "matched_rules": [
            {"rule_id": key[0], "version": key[1]} for key in sorted(matched_by_key)
        ],
        "trigger_domains": sorted(trigger_domains),
        "trigger_event_types": sorted(trigger_types),
    }
