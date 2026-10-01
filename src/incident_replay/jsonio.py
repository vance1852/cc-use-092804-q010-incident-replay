"""确定性的 JSON 处理与内容摘要。"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


def canonical_json(value: object) -> str:
    """生成跨平台一致、禁止非有限数值的紧凑 JSON 文本。"""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def content_digest(value: object) -> str:
    """对单个规范 JSON 值计算 SHA-256。"""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def digest_lines(values: Iterable[object]) -> str:
    """按输入顺序逐行计算摘要，用于事件批次。"""

    digest = hashlib.sha256()
    for value in values:
        digest.update(canonical_json(value).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(chr_code in frozenset("0123456789abcdef") for chr_code in value.lower())
    )
