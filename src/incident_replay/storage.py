"""现场异常回放服务的 SQLite 模式与事务辅助。"""

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
    role TEXT NOT NULL CHECK (role IN ('collector', 'analyst', 'approver', 'auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

-- 现场来源登记：每个模块时钟一个来源，固定归属一个域。
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL CHECK (domain IN ('control', 'ai', 'component')),
    label TEXT NOT NULL,
    registered_by TEXT NOT NULL REFERENCES users(user_id),
    registered_at TEXT NOT NULL
);

-- 不可变的时钟校准版本；版本号单调递增，永不原地修改。
CREATE TABLE IF NOT EXISTS calibration_versions (
    version INTEGER PRIMARY KEY AUTOINCREMENT,
    basis TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    published_by TEXT NOT NULL REFERENCES users(user_id),
    published_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS calibration_entries (
    version INTEGER NOT NULL REFERENCES calibration_versions(version),
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    drift_ppm TEXT NOT NULL,
    anchor_source TEXT NOT NULL,
    anchor_reference TEXT NOT NULL,
    PRIMARY KEY (version, source_id)
);

-- 调查案卷。状态机：open -> sealed -> reopening -> reopened -> sealed ...
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'sealed', 'reopening', 'reopened')),
    current_revision_no INTEGER,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    sealed_by TEXT REFERENCES users(user_id),
    sealed_at TEXT
);

-- 原始事件只追加。同一(案卷,来源,序列号)冲突直接拒绝，后到记录不能覆盖。
-- staged/rejected_late 用于封存后迟到证据，只有 active 参与时间线。
CREATE TABLE IF NOT EXISTS events (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    source_clock TEXT NOT NULL,
    event_type TEXT NOT NULL,
    content_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    arrival_rank INTEGER NOT NULL CHECK (arrival_rank > 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'staged', 'rejected_late')),
    reopen_request_id INTEGER,
    ingested_by TEXT NOT NULL REFERENCES users(user_id),
    ingested_at TEXT NOT NULL,
    UNIQUE (incident_id, source_id, sequence)
);

CREATE INDEX IF NOT EXISTS events_incident_rank ON events(incident_id, arrival_rank);

-- 不可变时间线版本；封存引用具体版本号。
CREATE TABLE IF NOT EXISTS incident_revisions (
    revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    revision_no INTEGER NOT NULL CHECK (revision_no > 0),
    calibration_version INTEGER NOT NULL REFERENCES calibration_versions(version),
    snapshot_json TEXT NOT NULL,
    timeline_sha256 TEXT NOT NULL CHECK (length(timeline_sha256) = 64),
    built_by TEXT NOT NULL REFERENCES users(user_id),
    built_at TEXT NOT NULL,
    UNIQUE (incident_id, revision_no)
);

-- 封存结论：一次封存一行，永不更新（复开后再次封存新增行）。
CREATE TABLE IF NOT EXISTS conclusions (
    conclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    revision_no INTEGER NOT NULL,
    timeline_sha256 TEXT NOT NULL CHECK (length(timeline_sha256) = 64),
    trigger_record_ids_json TEXT NOT NULL,
    decision_basis TEXT NOT NULL CHECK (decision_basis IN ('arrival_order', 'calibrated_order')),
    rationale TEXT NOT NULL,
    frozen_by TEXT NOT NULL REFERENCES users(user_id),
    frozen_at TEXT NOT NULL,
    UNIQUE (incident_id, revision_no)
);

CREATE TABLE IF NOT EXISTS reopen_requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT
);

-- 回退方案：冻结时按当时软件组合/跨域票据/安全规则推导，确认前不得执行。
CREATE TABLE IF NOT EXISTS rollback_plans (
    plan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    revision_no INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('proposed', 'confirmed', 'executing', 'completed')),
    basis_json TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK (length(plan_sha256) = 64),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    confirmed_by TEXT REFERENCES users(user_id),
    confirmed_at TEXT,
    UNIQUE (incident_id, revision_no)
);

CREATE TABLE IF NOT EXISTS plan_devices (
    plan_device_id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id INTEGER NOT NULL REFERENCES rollback_plans(plan_id),
    device_id TEXT NOT NULL,
    -- 触发事件点名但未登记于设备主数据时，域与组合为空，提示需要现场核实。
    domain TEXT,
    current_combo_id TEXT,
    reasons_json TEXT NOT NULL,
    candidate_actions_json TEXT NOT NULL,
    selected_action TEXT,
    exec_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (exec_status IN ('pending', 'executing', 'succeeded', 'failed')),
    executed_by TEXT REFERENCES users(user_id),
    executed_at TEXT,
    result_note TEXT,
    UNIQUE (plan_id, device_id)
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    revision_no INTEGER NOT NULL,
    role TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'notified')),
    notified_by TEXT REFERENCES users(user_id),
    notified_at TEXT,
    UNIQUE (incident_id, revision_no, role)
);

-- 推导所需的现场主数据：软件组合、设备清单、跨域票据、安全规则版本。
CREATE TABLE IF NOT EXISTS software_combos (
    combo_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL CHECK (domain IN ('control', 'ai', 'component')),
    components_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    registered_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL CHECK (domain IN ('control', 'ai', 'component')),
    combo_id TEXT REFERENCES software_combos(combo_id),
    registered_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    ticket_id TEXT PRIMARY KEY,
    summary TEXT NOT NULL,
    domains_json TEXT NOT NULL,
    combo_ids_json TEXT NOT NULL,
    device_ids_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    registered_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS safety_rules (
    rule_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    event_types_json TEXT NOT NULL,
    domains_json TEXT NOT NULL,
    components_json TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('rollback', 'isolate')),
    notify_roles_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    registered_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (rule_id, version)
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
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "users", "sources", "calibration_versions", "calibration_entries",
    "incidents", "events", "incident_revisions", "conclusions", "reopen_requests",
    "rollback_plans", "plan_devices", "notifications", "software_combos", "devices",
    "tickets", "safety_rules", "idempotency_keys", "audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    # HTTP 层为 ThreadingHTTPServer；全部写操作走 BEGIN IMMEDIATE 短事务并设 busy_timeout，
    # 因此允许连接跨工作线程使用。
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
    """初始化数据库结构，重复执行不改变已有数据。"""

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
