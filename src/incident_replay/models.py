"""上报事件与时钟校准输入的严格数据契约。"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence

from .clock import isoformat, parse_utc
from .jsonio import canonical_json, content_digest


class ValidationError(ValueError):
    """输入不能满足领域契约。"""


_DOMAINS = frozenset({"control", "ai", "component"})


def _require_mapping(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} 必须是对象")
    return value


def _require_sequence(value: object, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{path} 必须是数组")
    return value


def _required_text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} 必须是非空字符串")
    return value.strip()


def _decimal(value: object, path: str) -> Decimal:
    if isinstance(value, bool):
        raise ValidationError(f"{path} 必须是数值")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValidationError(f"{path} 必须是十进制数值") from exc
    if not result.is_finite():
        raise ValidationError(f"{path} 必须是有限数值")
    return result


@dataclass(frozen=True, slots=True)
class IncomingEvent:
    """模块上报的一条带时钟、序列号和摘要的现场事件。"""

    source_id: str
    sequence: int
    source_clock: str
    event_type: str
    content: Mapping[str, Any]
    content_sha256: str

    @classmethod
    def from_dict(cls, raw: object, path: str = "event") -> "IncomingEvent":
        data = _require_mapping(raw, path)
        source_id = _required_text(data.get("source_id"), f"{path}.source_id")
        sequence = data.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise ValidationError(f"{path}.sequence 必须是正整数")
        clock_value = _required_text(data.get("source_clock"), f"{path}.source_clock")
        parsed_clock = parse_utc(clock_value, f"{path}.source_clock")
        event_type = _required_text(data.get("event_type"), f"{path}.event_type")
        content = _require_mapping(data.get("content"), f"{path}.content")
        digest = _required_text(data.get("content_sha256"), f"{path}.content_sha256").lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValidationError(f"{path}.content_sha256 必须是 64 位十六进制 SHA-256")
        actual = content_digest(content)
        if actual != digest:
            raise ValidationError(
                f"{path}.content_sha256 与内容不符：期望 {actual}，收到 {digest}"
            )
        return cls(
            source_id=source_id,
            sequence=sequence,
            source_clock=isoformat(parsed_clock),
            event_type=event_type,
            content=dict(content),
            content_sha256=digest,
        )


@dataclass(frozen=True, slots=True)
class SourceCalibration:
    """单个来源时钟在校准版本中的换算参数。

    参考时间 = anchor_reference
        + (来源时间 - anchor_source) × (1 + drift_ppm × 10^-6)。
    锚点处的固定偏差隐含在 anchor_reference - anchor_source 中。
    """

    source_id: str
    drift_ppm: Decimal
    anchor_source: str
    anchor_reference: str

    @classmethod
    def from_dict(cls, raw: object, path: str) -> "SourceCalibration":
        data = _require_mapping(raw, path)
        source_id = _required_text(data.get("source_id"), f"{path}.source_id")
        drift_ppm = _decimal(data.get("drift_ppm"), f"{path}.drift_ppm")
        anchor_source = isoformat(parse_utc(
            _required_text(data.get("anchor_source"), f"{path}.anchor_source"),
            f"{path}.anchor_source",
        ))
        anchor_reference = isoformat(parse_utc(
            _required_text(data.get("anchor_reference"), f"{path}.anchor_reference"),
            f"{path}.anchor_reference",
        ))
        return cls(
            source_id=source_id,
            drift_ppm=drift_ppm,
            anchor_source=anchor_source,
            anchor_reference=anchor_reference,
        )

    @property
    def offset_seconds(self) -> Decimal:
        return (
            parse_utc(self.anchor_reference) - parse_utc(self.anchor_source)
        ).total_seconds()

    def normalized(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "drift_ppm": format(self.drift_ppm, "f"),
            "anchor_source": self.anchor_source,
            "anchor_reference": self.anchor_reference,
            "offset_seconds": format(Decimal(str(self.offset_seconds)), "f"),
        }


@dataclass(frozen=True, slots=True)
class SafetyRuleInput:
    """一条安全规则版本的输入。"""

    rule_id: str
    version: int
    event_types: frozenset[str]
    domains: frozenset[str]
    components: frozenset[str]
    action: str
    notify_roles: frozenset[str]

    @classmethod
    def from_dict(cls, raw: object) -> "SafetyRuleInput":
        data = _require_mapping(raw, "rule")
        version = data.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValidationError("rule.version 必须是正整数")
        event_types = frozenset(
            _required_text(item, "rule.event_types[]")
            for item in _require_sequence(data.get("event_types"), "rule.event_types")
        )
        if not event_types:
            raise ValidationError("rule.event_types 不能为空")
        domains = frozenset(
            _required_text(item, "rule.domains[]")
            for item in _require_sequence(data.get("domains", []), "rule.domains")
        )
        unknown_domains = domains - _DOMAINS
        if unknown_domains:
            raise ValidationError(f"rule.domains 含未知域: {sorted(unknown_domains)}")
        components = frozenset(
            _required_text(item, "rule.components[]")
            for item in _require_sequence(data.get("components", []), "rule.components")
        )
        action = _required_text(data.get("action"), "rule.action")
        if action not in {"rollback", "isolate"}:
            raise ValidationError("rule.action 必须是 rollback 或 isolate")
        notify_roles = frozenset(
            _required_text(item, "rule.notify_roles[]")
            for item in _require_sequence(data.get("notify_roles"), "rule.notify_roles")
        )
        if not notify_roles:
            raise ValidationError("rule.notify_roles 不能为空")
        return cls(
            rule_id=_required_text(data.get("rule_id"), "rule.rule_id"),
            version=version,
            event_types=event_types,
            domains=domains,
            components=components,
            action=action,
            notify_roles=notify_roles,
        )

    def normalized(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "event_types": sorted(self.event_types),
            "domains": sorted(self.domains),
            "components": sorted(self.components),
            "action": self.action,
            "notify_roles": sorted(self.notify_roles),
        }
