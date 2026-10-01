"""现场异常回放领域的严格输入契约。

所有外部输入先经过本模块校验，禁止布尔冒充整数、禁止缺时区时间戳、
禁止内容摘要长度不合规。时间戳统一由 ``clock.parse_utc`` 归一为带时区的 UTC。
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence

from .clock import parse_utc
from .errors import ValidationFailed

EVENT_KINDS = frozenset({
    "control_receipt",  # 控制回执
    "ai_decision",      # AI 决策
    "component_alarm",  # 部件告警
    "operator_note",    # 人工备注
    "gateway_sync",     # 网关时钟同步标记
})

CALIBRATION_KINDS = frozenset({"offset", "anchor"})
TIMELINE_ANOMALIES = frozenset({
    "duplicate_sequence",  # 同源序列号重复且内容冲突
    "duplicate_content",   # 同源序列号重复但内容一致（重传）
    "sequence_gap",        # 同源序列号缺口
    "ordering_conflict",   # 到达顺序与校准时间顺序矛盾
    "clock_drift",         # 源时钟漂移超出阈值
})


def _mapping(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationFailed(f"{path} 必须是对象")
    return value


def _sequence(value: object, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationFailed(f"{path} 必须是数组")
    return value


def _required_text(value: object, path: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{path} 必须是非空字符串")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{path} 不能超过 {maximum} 个字符")
    return result


def _optional_text(value: object, path: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return _required_text(value, path, maximum)


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationFailed(f"{path} 必须是整数")
    return value


def _sha256(value: object, path: str) -> str:
    result = _required_text(value, path, 64)
    if len(result) != 64 or any(char not in "0123456789abcdefABCDEF" for char in result):
        raise ValidationFailed(f"{path} 必须是 64 位十六进制 SHA-256")
    return result.lower()


def _decimal(value: object, path: str) -> Decimal:
    if isinstance(value, bool):
        raise ValidationFailed(f"{path} 必须是数值")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValidationFailed(f"{path} 必须是十进制数值") from exc
    if not result.is_finite():
        raise ValidationFailed(f"{path} 必须是有限数值")
    return result


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """带来源时钟、序列号和内容摘要的现场事件。"""

    source_id: str
    sequence: int
    source_clock: str          # 来源设备本地时钟 ISO 8601（必须带时区）
    content_digest: str        # 事件正文 64 位 SHA-256
    kind: str
    incident_ref: str | None   # 事件正文内引用的异常/急停编号
    device_ref: str | None     # 事件正文内引用的设备编号
    payload: Mapping[str, Any]

    @classmethod
    def from_dict(cls, raw: object, path: str = "event") -> "EventEnvelope":
        data = _mapping(raw, path)
        kind = _required_text(data.get("kind"), f"{path}.kind", 32)
        if kind not in EVENT_KINDS:
            raise ValidationFailed(f"{path}.kind 不受支持: {kind}")
        sequence = _integer(data.get("sequence"), f"{path}.sequence")
        if sequence < 0:
            raise ValidationFailed(f"{path}.sequence 不能为负")
        clock_text = _required_text(data.get("source_clock"), f"{path}.source_clock", 40)
        try:
            parse_utc(clock_text, f"{path}.source_clock")
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        payload = data.get("payload", {})
        if not isinstance(payload, Mapping):
            raise ValidationFailed(f"{path}.payload 必须是对象")
        digest = _sha256(data.get("content_digest"), f"{path}.content_digest")
        incident_ref = _optional_text(data.get("incident_ref"), f"{path}.incident_ref", 64)
        device_ref = _optional_text(data.get("device_ref"), f"{path}.device_ref", 64)
        return cls(
            source_id=_required_text(data.get("source_id"), f"{path}.source_id", 64),
            sequence=sequence,
            source_clock=clock_text,
            content_digest=digest,
            kind=kind,
            incident_ref=incident_ref,
            device_ref=device_ref,
            payload=dict(payload),
        )


@dataclass(frozen=True, slots=True)
class CalibrationInput:
    """一次时钟校准依据：固定偏移或锚点对（源时钟 ↔ 权威时钟）。"""

    source_id: str
    kind: str
    effective_at: str         # 权威时钟时间，校准从此刻起适用
    offset_ms: Decimal        # 校准后时间 = 源时间 + offset_ms（anchor 亦显式换算）
    reference_at: str | None  # anchor 配对的权威时钟
    basis: str

    @classmethod
    def from_dict(cls, raw: object, path: str = "calibration") -> "CalibrationInput":
        data = _mapping(raw, path)
        kind = _required_text(data.get("kind"), f"{path}.kind", 16)
        if kind not in CALIBRATION_KINDS:
            raise ValidationFailed(f"{path}.kind 必须是 offset 或 anchor")
        source_id = _required_text(data.get("source_id"), f"{path}.source_id", 64)
        effective_at = _required_text(data.get("effective_at"), f"{path}.effective_at", 40)
        try:
            parse_utc(effective_at, f"{path}.effective_at")
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        offset_ms: Decimal | None = None
        reference_at = None
        if kind == "offset":
            offset_ms = _decimal(data.get("offset_ms"), f"{path}.offset_ms")
        else:
            source_at = _required_text(data.get("source_at"), f"{path}.source_at", 40)
            reference_at = _required_text(data.get("reference_at"), f"{path}.reference_at", 40)
            try:
                source_dt = parse_utc(source_at, f"{path}.source_at")
                reference_dt = parse_utc(reference_at, f"{path}.reference_at")
            except ValueError as exc:
                raise ValidationFailed(str(exc)) from exc
            delta = reference_dt - source_dt
            total_microseconds = (
                (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
            )
            offset_ms = Decimal(total_microseconds) / Decimal(1_000)
        return cls(
            source_id=source_id,
            kind=kind,
            effective_at=effective_at,
            offset_ms=offset_ms,
            reference_at=reference_at,
            basis=_required_text(data.get("basis"), f"{path}.basis", 256),
        )


@dataclass(frozen=True, slots=True)
class SoftwareComponent:
    """冻结时在场的一个软件组合部件。"""

    component: str
    version: str
    digest: str

    @classmethod
    def from_dict(cls, raw: object, path: str) -> "SoftwareComponent":
        data = _mapping(raw, path)
        return cls(
            component=_required_text(data.get("component"), f"{path}.component", 64),
            version=_required_text(data.get("version"), f"{path}.version", 64),
            digest=_sha256(data.get("digest"), f"{path}.digest"),
        )
