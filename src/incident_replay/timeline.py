"""确定性时间线构建与异常检测。

同一份（事件集合, 校准集合, 漂移阈值）输入必然得到同一条时间线与同一个摘要：

- 原始到达顺序永不改写：``arrival_seq`` 由入库时单调分配并全程保留；
- 校准时间只用于形成排序视图，绝不覆盖来源时钟字段；
- 同源同序列号重复（无论内容是否一致）都显式标注，不做最后到达覆盖；
- 序列号缺口、到达顺序与校准顺序矛盾、同源时钟漂移均生成结构化异常。
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Mapping, Sequence

from .clock import parse_utc
from .jsonio import canonical_json, hex_digest

DEFAULT_DRIFT_THRESHOLD_MS = Decimal("50")


@dataclass(frozen=True, slots=True)
class EventPoint:
    arrival_seq: int
    source_id: str
    sequence: int
    kind: str
    source_clock: str
    received_at: str
    content_digest: str
    device_ref: str | None = None

    @property
    def source_dt(self) -> datetime:
        return parse_utc(self.source_clock)

    @property
    def received_dt(self) -> datetime:
        return parse_utc(self.received_at)


@dataclass(frozen=True, slots=True)
class CalibrationPoint:
    version: int
    source_id: str
    kind: str
    effective_at: str
    offset_ms: Decimal
    basis: str

    @property
    def effective_dt(self) -> datetime:
        return parse_utc(self.effective_at)


def _anomaly(code: str, detail: str, **refs: Any) -> dict[str, Any]:
    item = {"code": code, "detail": detail}
    item.update(sorted(refs.items()))
    return item


def select_calibration(
    source_dt: datetime, calibrations: Sequence[CalibrationPoint]
) -> CalibrationPoint | None:
    """选择适用于事件的校准版本。

    规则：在所有满足 ``effective_at <= 源时间 + offset_ms`` 的校准行中，
    取生效时间最晚者；生效时间相同取版本号最大者。该规则完全确定，
    不依赖插入时刻或网络到达顺序。无校准行满足时事件保持未校准状态。
    """

    candidates: list[CalibrationPoint] = []
    for cal in calibrations:
        calibrated = source_dt + _offset_delta(cal.offset_ms)
        if calibrated >= cal.effective_dt:
            candidates.append(cal)
    if not candidates:
        return None
    return max(candidates, key=lambda cal: (cal.effective_dt, cal.version))


def _offset_delta(offset_ms: Decimal):
    from datetime import timedelta

    microseconds = int((offset_ms * Decimal(1000)).to_integral_value())
    return timedelta(microseconds=microseconds)


def _delta_microseconds(delta) -> int:
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def build_timeline(
    events: Sequence[EventPoint],
    calibrations: Sequence[CalibrationPoint],
    drift_threshold_ms: Decimal = DEFAULT_DRIFT_THRESHOLD_MS,
) -> dict[str, Any]:
    """构建确定性时间线并标出冲突、缺口与时钟漂移。"""

    threshold = Decimal(drift_threshold_ms)
    cals_by_source: dict[str, list[CalibrationPoint]] = {}
    for cal in calibrations:
        cals_by_source.setdefault(cal.source_id, []).append(cal)
    for source_cals in cals_by_source.values():
        source_cals.sort(key=lambda cal: (cal.effective_dt, cal.version))

    entries: dict[int, dict[str, Any]] = {}
    for event in sorted(events, key=lambda item: item.arrival_seq):
        cal = select_calibration(event.source_dt, cals_by_source.get(event.source_id, ()))
        if cal is None:
            calibrated_at: str | None = None
            cal_version: int | None = None
        else:
            calibrated_dt = event.source_dt + _offset_delta(cal.offset_ms)
            from .clock import isoformat

            calibrated_at = isoformat(calibrated_dt)
            cal_version = cal.version
        entries[event.arrival_seq] = {
            "arrival_seq": event.arrival_seq,
            "source_id": event.source_id,
            "sequence": event.sequence,
            "kind": event.kind,
            "source_clock": event.source_clock,
            "received_at": event.received_at,
            "calibrated_at": calibrated_at,
            "calibration_version": cal_version,
            "content_digest": event.content_digest,
            "device_ref": event.device_ref,
            "anomalies": [],
        }

    global_anomalies: list[dict[str, Any]] = []

    def flag(arrival_seq: int, anomaly: dict[str, Any]) -> None:
        entries[arrival_seq]["anomalies"].append(anomaly)

    # 1) 同源序列号重复：内容一致=重传；内容冲突=矛盾证据，全部保留。
    groups: dict[tuple[str, int], list[EventPoint]] = {}
    for event in events:
        groups.setdefault((event.source_id, event.sequence), []).append(event)
    for (source_id, sequence), members in sorted(groups.items()):
        if len(members) == 1:
            continue
        members = sorted(members, key=lambda item: item.arrival_seq)
        digests = {member.content_digest for member in members}
        if len(digests) == 1:
            code = "duplicate_content"
            detail = f"源 {source_id} 序列号 {sequence} 被重复送达，内容一致（重传）"
        else:
            code = "duplicate_sequence"
            detail = f"源 {source_id} 序列号 {sequence} 的多条记录内容摘要互相冲突"
        seqs = [member.arrival_seq for member in members]
        global_anomalies.append(
            _anomaly(code, detail, source_id=source_id, sequence=sequence, arrival_seqs=seqs)
        )
        for member in members:
            flag(
                member.arrival_seq,
                _anomaly(code, detail, other_arrival_seqs=[s for s in seqs if s != member.arrival_seq]),
            )

    # 2) 同源序列号缺口（仅检测已观测到的最小区间内部缺口）。
    by_source: dict[str, list[EventPoint]] = {}
    for event in events:
        by_source.setdefault(event.source_id, []).append(event)
    for source_id, members in sorted(by_source.items()):
        observed = sorted({member.sequence for member in members})
        observed_set = set(observed)
        missing = [value for value in range(observed[0], observed[-1] + 1) if value not in observed_set]
        for missing_seq in missing:
            next_index = bisect.bisect_right(observed, missing_seq)
            next_seq = observed[next_index]
            anchor = min(
                (member for member in members if member.sequence == next_seq),
                key=lambda item: item.arrival_seq,
            )
            detail = f"源 {source_id} 序列号 {missing_seq} 缺失（观测区间 {observed[0]}..{observed[-1]}）"
            global_anomalies.append(
                _anomaly(code="sequence_gap", detail=detail, source_id=source_id, sequence=missing_seq)
            )
            flag(
                anchor.arrival_seq,
                _anomaly("sequence_gap", detail, missing_sequence=missing_seq),
            )

    # 3) 时钟漂移：同源相邻事件（按序列号）校准时间增量与到达增量之差超阈值。
    for source_id, members in sorted(by_source.items()):
        ordered = sorted(members, key=lambda item: (item.sequence, item.arrival_seq))
        for previous, current in zip(ordered, ordered[1:]):
            prev_entry = entries[previous.arrival_seq]
            cur_entry = entries[current.arrival_seq]
            if (
                prev_entry["calibrated_at"] is None
                or cur_entry["calibrated_at"] is None
                or prev_entry["calibration_version"] != cur_entry["calibration_version"]
            ):
                # 未校准或跨越校准版本边界的偏差由校准变更解释，不算漂移。
                continue
            cal_delta = parse_utc(cur_entry["calibrated_at"]) - parse_utc(prev_entry["calibrated_at"])
            recv_delta = current.received_dt - previous.received_dt
            residual_us = _delta_microseconds(cal_delta) - _delta_microseconds(recv_delta)
            residual_ms = Decimal(residual_us) / Decimal(1000)
            if abs(residual_ms) > threshold:
                detail = (
                    f"源 {source_id} 序列号 {previous.sequence}->{current.sequence} "
                    f"时钟漂移残差 {residual_ms} 毫秒，超过阈值 {threshold} 毫秒"
                )
                global_anomalies.append(
                    _anomaly(
                        "clock_drift",
                        detail,
                        source_id=source_id,
                        arrival_seqs=[previous.arrival_seq, current.arrival_seq],
                        residual_ms=format(residual_ms, "f"),
                        threshold_ms=format(threshold, "f"),
                    )
                )
                flag(
                    current.arrival_seq,
                    _anomaly(
                        "clock_drift",
                        detail,
                        previous_arrival_seq=previous.arrival_seq,
                        residual_ms=format(residual_ms, "f"),
                    ),
                )

    # 4) 到达顺序与校准时间顺序的矛盾（仅对已校准事件两两判定）。
    calibrated = [
        event for event in sorted(events, key=lambda item: item.arrival_seq)
        if entries[event.arrival_seq]["calibrated_at"] is not None
    ]
    for i, earlier in enumerate(calibrated):
        for later in calibrated[i + 1:]:
            earlier_at = parse_utc(entries[earlier.arrival_seq]["calibrated_at"])
            later_at = parse_utc(entries[later.arrival_seq]["calibrated_at"])
            if earlier_at > later_at:
                detail = (
                    f"到达序 {earlier.arrival_seq} 晚于 {later.arrival_seq}，"
                    "但校准时间相反，人工拼接顺序与时钟证据冲突"
                )
                global_anomalies.append(
                    _anomaly(
                        "ordering_conflict",
                        detail,
                        arrival_seqs=[earlier.arrival_seq, later.arrival_seq],
                    )
                )
                flag(
                    earlier.arrival_seq,
                    _anomaly("ordering_conflict", detail, other_arrival_seq=later.arrival_seq),
                )
                flag(
                    later.arrival_seq,
                    _anomaly("ordering_conflict", detail, other_arrival_seq=earlier.arrival_seq),
                )

    ordered_view = sorted(
        entries.values(),
        key=lambda item: (
            item["calibrated_at"] is None,
            item["calibrated_at"] or "",
            item["arrival_seq"],
        ),
    )
    calibration_version = max((cal.version for cal in calibrations), default=0)
    timeline = {
        "calibration_version": calibration_version,
        "drift_threshold_ms": format(threshold, "f"),
        "event_count": len(events),
        "uncalibrated_count": sum(1 for item in entries.values() if item["calibrated_at"] is None),
        "arrival_order": [event.arrival_seq for event in sorted(events, key=lambda item: item.arrival_seq)],
        "entries": ordered_view,
        "anomalies": sorted(
            global_anomalies,
            key=lambda item: canonical_json(item),
        ),
    }
    timeline["timeline_sha256"] = timeline_digest(timeline)
    return timeline


def timeline_digest(timeline: Mapping[str, Any]) -> str:
    """对时间线的可复算部分计算摘要（不含摘要字段自身）。"""

    material = {key: value for key, value in timeline.items() if key != "timeline_sha256"}
    return hex_digest(material)
