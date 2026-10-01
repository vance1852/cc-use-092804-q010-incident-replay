"""确定性时间线推导。

输入不可变的事件记录（含原始到达序号）和一个校准版本，输出：

- 到达顺序：事件被接收的原始顺序，永不重排；
- 校准时间线：按参考时钟换算后确定性排序（校准时间、来源序列号、到达序号）；
- 显式标注：跨源时间冲突、来源序列号缺口、时钟漂移/未校准来源。

标注是数据而不是裁决：冲突不会被后到记录覆盖，调查人在封存时必须选择决定依据。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Mapping, Sequence

from .clock import parse_utc
from .models import SourceCalibration

# 换算结果保留的小数位数（纳秒级），保证排序与摘要跨进程一致。
TIMESTAMP_QUANTUM = "0.000000001"


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    record_id: int
    source_id: str
    sequence: int
    source_clock: str
    event_type: str
    content: Mapping[str, Any]
    content_sha256: str
    arrival_rank: int
    reference_clock: str
    calibration_status: str  # calibrated | uncalibrated


@dataclass(frozen=True, slots=True)
class TimelineAnnotation:
    kind: str  # conflict | gap | drift | uncalibrated_source
    severity: str  # info | warning | critical
    source_id: str | None
    detail: str
    record_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Timeline:
    calibration_version: int
    arrival_order: tuple[TimelineEvent, ...]
    calibrated_order: tuple[TimelineEvent, ...]
    annotations: tuple[TimelineAnnotation, ...]
    timeline_sha256: str


def _quantize(value: Decimal) -> Decimal:
    return value.quantize(Decimal(TIMESTAMP_QUANTUM))


def _fixed_utc(value) -> str:
    """固定微秒精度的 UTC 文本，保证字符串字典序与时间顺序一致。"""

    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def convert_reference(event_clock: str, calibration: SourceCalibration) -> str:
    anchor_source = parse_utc(calibration.anchor_source)
    anchor_reference = parse_utc(calibration.anchor_reference)
    elapsed = (parse_utc(event_clock) - anchor_source).total_seconds()
    corrected = anchor_reference + timedelta(
        seconds=float(_quantize(Decimal(str(elapsed)) * (Decimal(1) + calibration.drift_ppm / Decimal(1_000_000))))
    )
    return _fixed_utc(corrected)


def _event_json(event: TimelineEvent) -> dict[str, object]:
    return {
        "record_id": event.record_id,
        "source_id": event.source_id,
        "sequence": event.sequence,
        "source_clock": event.source_clock,
        "reference_clock": event.reference_clock,
        "event_type": event.event_type,
        "content": event.content,
        "content_sha256": event.content_sha256,
        "arrival_rank": event.arrival_rank,
        "calibration_status": event.calibration_status,
    }


def build_timeline(
    records: Sequence[Mapping[str, Any]],
    calibrations: Mapping[str, SourceCalibration],
    calibration_version: int,
    *,
    conflict_window_ms: int = 5,
    drift_warn_ppm: Decimal = Decimal("100"),
    digest_fn=None,
) -> Timeline:
    """从原始记录与校准版本推导时间线。

    records 每项至少含 record_id/source_id/sequence/source_clock/event_type/content/
    content_sha256/arrival_rank 字段，顺序无关（内部按 arrival_rank 稳定排序）。
    """

    from .jsonio import content_digest

    digest_fn = digest_fn or content_digest
    ordered = sorted(records, key=lambda row: int(row["arrival_rank"]))

    events: list[TimelineEvent] = []
    by_source: dict[str, list[TimelineEvent]] = {}
    annotations: list[TimelineAnnotation] = []
    warned_drift: set[str] = set()

    for row in ordered:
        source_id = row["source_id"]
        calibration = calibrations.get(source_id)
        if calibration is None:
            status = "uncalibrated"
            reference = row["source_clock"]
            annotations.append(TimelineAnnotation(
                kind="uncalibrated_source",
                severity="warning",
                source_id=source_id,
                detail=f"来源 {source_id} 没有校准版本 {calibration_version} 的换算参数，按来源时钟挂在时间线末尾",
                record_ids=(int(row["record_id"]),),
            ))
        else:
            status = "calibrated"
            reference = convert_reference(row["source_clock"], calibration)
            if abs(calibration.drift_ppm) >= drift_warn_ppm and source_id not in warned_drift:
                warned_drift.add(source_id)
                annotations.append(TimelineAnnotation(
                    kind="drift",
                    severity="warning",
                    source_id=source_id,
                    detail=(
                        f"来源 {source_id} 时钟漂移 {format(calibration.drift_ppm, 'f')} ppm "
                        f"达到告警阈值 {format(drift_warn_ppm, 'f')} ppm"
                    ),
                    record_ids=(),
                ))
        event = TimelineEvent(
            record_id=int(row["record_id"]),
            source_id=source_id,
            sequence=int(row["sequence"]),
            source_clock=row["source_clock"],
            event_type=row["event_type"],
            content=dict(row["content"]),
            content_sha256=row["content_sha256"],
            arrival_rank=int(row["arrival_rank"]),
            reference_clock=reference,
            calibration_status=status,
        )
        events.append(event)
        by_source.setdefault(source_id, []).append(event)

    # 序列号缺口：按来源序列号检查连续性（缺口不依赖时间，永远标注）。
    for source_id, source_events in sorted(by_source.items()):
        sequences = sorted(item.sequence for item in source_events)
        missing: list[int] = []
        for previous, current in zip(sequences, sequences[1:]):
            missing.extend(range(previous + 1, current))
        if missing:
            annotations.append(TimelineAnnotation(
                kind="gap",
                severity="critical",
                source_id=source_id,
                detail=f"来源 {source_id} 的序列号缺失 {missing}",
                record_ids=tuple(item.record_id for item in source_events),
            ))

    calibrated_order = tuple(sorted(
        (event for event in events if event.calibration_status == "calibrated"),
        key=lambda event: (event.reference_clock, event.source_id, event.sequence, event.arrival_rank),
    ))

    # 跨源冲突：不同来源的事件落入同一个校准时间窗口，其先后差小于时钟不确定性，
    # 仅凭时间无法确定因果（这正是“人工拼接成不同顺序”的机器刻画）。
    # 若到达顺序还与校准顺序相反，则为最高严重度：两种排序给出相反结论。
    window = timedelta(milliseconds=conflict_window_ms)
    seen_conflicts: set[tuple[int, int]] = set()
    calibrated_events = list(calibrated_order)
    for index, earlier in enumerate(calibrated_events):
        earlier_time = parse_utc(earlier.reference_clock)
        for later in calibrated_events[index + 1:]:
            later_time = parse_utc(later.reference_clock)
            if later_time - earlier_time > window:
                break
            if later.source_id == earlier.source_id:
                continue
            pair = tuple(sorted((earlier.record_id, later.record_id)))
            if pair in seen_conflicts:
                continue
            seen_conflicts.add(pair)  # type: ignore[arg-type]
            reversed_arrival = later.arrival_rank < earlier.arrival_rank
            annotations.append(TimelineAnnotation(
                kind="conflict",
                severity="critical" if reversed_arrival else "warning",
                source_id=None,
                detail=(
                    f"记录 {earlier.record_id}({earlier.source_id}#{earlier.sequence}) 与 "
                    f"{later.record_id}({later.source_id}#{later.sequence}) 校准时间相差 "
                    f"{(later_time - earlier_time).total_seconds() * 1000:.0f}ms，小于冲突窗口，"
                    + ("且到达顺序与校准顺序相反，" if reversed_arrival else "")
                    + "触发先后无法仅凭时间判定；时间线按(校准时间,来源,序列号,到达序号)确定性排序但不做因果裁决"
                ),
                record_ids=(earlier.record_id, later.record_id),
            ))

    # 标注按 (kind, 首记录, 文本) 稳定排序，保证输出确定。
    annotations.sort(key=lambda item: (item.kind, item.record_ids, item.detail))

    payload = {
        "calibration_version": calibration_version,
        "arrival_order": [_event_json(event) for event in events],
        "calibrated_order": [_event_json(event) for event in calibrated_order],
        "annotations": [
            {
                "kind": item.kind,
                "severity": item.severity,
                "source_id": item.source_id,
                "detail": item.detail,
                "record_ids": list(item.record_ids),
            }
            for item in annotations
        ],
    }
    return Timeline(
        calibration_version=calibration_version,
        arrival_order=tuple(events),
        calibrated_order=calibrated_order,
        annotations=tuple(annotations),
        timeline_sha256=digest_fn(payload),
    )
