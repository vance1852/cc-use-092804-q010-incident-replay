"""现场异常回放服务的 SQLite 模式与事务辅助。

封存结论（``revision_snapshots``）只追加、不更新；迟到证据通过新的
``arrival_seq`` 与新修订版本进入系统，任何路径都不会改写历史行。
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN (
        'field_engineer', 'investigator', 'safety_officer', 'dispatcher', 'auditor'
    )),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'collecting', 'frozen', 'reopened', 'closed'
    )),
    drift_threshold_ms TEXT NOT NULL,
    current_revision INTEGER NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    frozen_by TEXT REFERENCES users(user_id),
    frozen_at TEXT
);

-- 设备台账与设备上实际部署的软件组合（冻结时整体快照）。
CREATE TABLE IF NOT EXISTS devices (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    device_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    owner_team TEXT NOT NULL,
    contacts_json TEXT NOT NULL,
    registered_by TEXT NOT NULL REFERENCES users(user_id),
    registered_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, device_id)
);

CREATE TABLE IF NOT EXISTS deployments (
    incident_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    component TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (length(digest) = 64),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, device_id, component),
    FOREIGN KEY (incident_id, device_id) REFERENCES devices(incident_id, device_id)
);

-- 跨域票据（控制域 / AI 计算域 / 部件质量域）。
CREATE TABLE IF NOT EXISTS tickets (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    ticket_id TEXT NOT NULL,
    domain TEXT NOT NULL CHECK (domain IN ('control', 'ai_compute', 'component_quality')),
    title TEXT NOT NULL,
    device_ids_json TEXT NOT NULL,
    components_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'mitigated', 'closed')),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, ticket_id)
);

-- 安全规则：命中事件类型即触发候选回退动作与通知范围。
CREATE TABLE IF NOT EXISTS safety_rules (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    event_kinds_json TEXT NOT NULL,
    components_json TEXT NOT NULL,
    action_kind TEXT NOT NULL,
    rollback_target TEXT NOT NULL,
    priority INTEGER NOT NULL,
    notify_roles_json TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, rule_id)
);

-- 时钟校准版本，版本号在单个异常内单调递增，只追加。
CREATE TABLE IF NOT EXISTS calibrations (
    calibration_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    version INTEGER NOT NULL CHECK (version > 0),
    source_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('offset', 'anchor')),
    effective_at TEXT NOT NULL,
    offset_ms TEXT NOT NULL,
    reference_at TEXT,
    basis TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (incident_id, version)
);

-- 现场事件：arrival_seq 单调分配，同源同序列号同摘要的重传被拒绝，
-- 但同源同序列号不同摘要全部保留并在时间线上标冲突。
CREATE TABLE IF NOT EXISTS events (
    arrival_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    source_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    source_clock TEXT NOT NULL,
    received_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    incident_ref TEXT,
    device_ref TEXT,
    content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
    payload_json TEXT NOT NULL,
    recorded_by TEXT NOT NULL REFERENCES users(user_id),
    recorded_at TEXT NOT NULL,
    after_revision INTEGER NOT NULL DEFAULT 0
);

-- 封存修订：时间线、软件组合、影响推导结果均以规范化 JSON 固化，绝不更新。
CREATE TABLE IF NOT EXISTS revision_snapshots (
    incident_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    calibration_version INTEGER NOT NULL,
    drift_threshold_ms TEXT NOT NULL,
    timeline_json TEXT NOT NULL,
    timeline_sha256 TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    impact_json TEXT NOT NULL,
    notify_scope_json TEXT NOT NULL,
    rationale TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, revision)
);

CREATE TABLE IF NOT EXISTS reopen_requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    from_revision INTEGER NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT
);

CREATE TABLE IF NOT EXISTS rollback_plans (
    plan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    revision INTEGER NOT NULL,
    rationale TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('proposed', 'approved', 'rejected', 'cancelled')),
    plan_sha256 TEXT NOT NULL,
    proposed_by TEXT NOT NULL REFERENCES users(user_id),
    proposed_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT,
    FOREIGN KEY (incident_id, revision) REFERENCES revision_snapshots(incident_id, revision)
);

CREATE TABLE IF NOT EXISTS rollback_actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id INTEGER NOT NULL REFERENCES rollback_plans(plan_id),
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    device_id TEXT NOT NULL,
    action_kind TEXT NOT NULL,
    target TEXT NOT NULL,
    priority INTEGER NOT NULL,
    rule_ids_json TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'pending', 'in_progress', 'succeeded', 'failed', 'skipped'
    )),
    updated_by TEXT REFERENCES users(user_id),
    updated_at TEXT,
    result_note TEXT,
    UNIQUE (plan_id, device_id, action_kind, target)
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    revision INTEGER NOT NULL,
    audience_json TEXT NOT NULL,
    recipients_json TEXT NOT NULL,
    channel TEXT NOT NULL,
    subject TEXT NOT NULL,
    rationale TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    dispatched_at TEXT
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS events_incident_idx ON events(incident_id, arrival_seq);
CREATE INDEX IF NOT EXISTS actions_incident_idx ON rollback_actions(incident_id, action_id);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "users", "incidents", "devices", "deployments", "tickets",
    "safety_rules", "calibrations", "events", "revision_snapshots",
    "reopen_requests", "rollback_plans", "rollback_actions", "notifications",
    "idempotency_keys", "audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用外键与繁忙等待。

    ``check_same_thread=False`` 让 ThreadingHTTPServer 的工作线程可以共用连接；
    所有写事务均以 ``BEGIN IMMEDIATE`` 开始，配合 busy_timeout 完成串行化。
    """

    connection = sqlite3.connect(
        str(path), isolation_level=None, check_same_thread=False
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    """初始化模式，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
