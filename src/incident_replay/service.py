"""现场异常回放的领域用例。

关键不变量：

- 事件只追加：``arrival_seq`` 单调，任何写入路径都不更新或删除历史事件；
- 封存修订只追加：迟到证据只能经复开流程形成新修订，旧快照原样保留；
- 回退计划的提出（调查负责人）与批准（另一名安全授权者）强制职责分离；
- 时间线与影响推导全部由已固化的输入确定性复算，不采信最后到达者。
"""

from __future__ import annotations

import json
import sqlite3
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .clock import SystemClock, isoformat
from .contracts import (
    EVENT_KINDS,
    TIMELINE_ANOMALIES,
    CalibrationInput,
    EventEnvelope,
)
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .impact import ACTION_KINDS, ANOMALY_TRIGGER_PREFIX, derive_impact
from .jsonio import canonical_json, content_digest, hex_digest
from .storage import initialize, transaction
from .timeline import DEFAULT_DRIFT_THRESHOLD_MS, CalibrationPoint, EventPoint, build_timeline

ROLES = frozenset({"field_engineer", "investigator", "safety_officer", "dispatcher", "auditor"})

ROLE_PERMISSIONS = {
    "field_engineer": {
        "incident.create", "context.register", "event.ingest", "report.read",
    },
    "investigator": {
        "calibration.write", "incident.freeze", "incident.close",
        "reopen.request", "plan.propose", "plan.cancel", "report.read",
    },
    "safety_officer": {
        "plan.review", "action.update", "reopen.review", "incident.close",
        "notification.dispatch", "report.read",
    },
    "dispatcher": {"notification.dispatch", "report.read"},
    "auditor": {"report.read", "audit.read"},
}

TICKET_DOMAINS = frozenset({"control", "ai_compute", "component_quality"})
ACTION_STATUSES = ("pending", "in_progress", "succeeded", "failed", "skipped")
ACTION_TRANSITIONS = {
    "pending": {"in_progress", "skipped"},
    "in_progress": {"succeeded", "failed"},
    "succeeded": set(),
    "failed": {"in_progress"},   # 失败允许重试
    "skipped": set(),
}


class ReplayService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    # ------------------------------------------------------------------ 基础

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLES:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    # ------------------------------------------------------------ 异常单管理

    def create_incident(
        self, actor_id: str, incident_id: str, title: str, drift_threshold_ms: str | float | Decimal | None = None
    ) -> dict[str, Any]:
        self._require(actor_id, "incident.create")
        threshold = self._threshold(drift_threshold_ms)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO incidents(incident_id,title,state,drift_threshold_ms,current_revision,"
                    "created_by,created_at) VALUES(?,?,'collecting',?,0,?,?)",
                    (incident_id, title, format(threshold, "f"), actor_id, self._now()),
                )
                self._audit("incident", incident_id, "incident.created", actor_id, {"title": title})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"异常单已存在: {incident_id}") from exc
        return self.get_incident(incident_id)

    @staticmethod
    def _threshold(value: str | float | Decimal | None) -> Decimal:
        if value is None:
            return DEFAULT_DRIFT_THRESHOLD_MS
        try:
            threshold = Decimal(str(value))
        except Exception as exc:
            raise ValidationFailed("drift_threshold_ms 必须是非负十进制数值（毫秒）") from exc
        if not threshold.is_finite() or threshold < 0:
            raise ValidationFailed("drift_threshold_ms 必须是非负有限数值")
        return threshold

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise NotFound("异常单不存在")
        return dict(row)

    def _incident_row(self, incident_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise NotFound("异常单不存在")
        return row

    def _require_open_for_evidence(self, incident: sqlite3.Row) -> None:
        if incident["state"] not in {"collecting", "reopened"}:
            raise InvalidState(
                "回放已封存：迟到证据不能直接写入，请先提交复开申请，复算后形成新修订版本"
            )

    # --------------------------------------------------------- 现场背景登记

    def register_device(
        self,
        actor_id: str,
        incident_id: str,
        device_id: str,
        kind: str,
        owner_team: str,
        contacts: Iterable[str] = (),
    ) -> dict[str, Any]:
        self._require(actor_id, "context.register")
        incident = self._incident_row(incident_id)
        self._require_open_for_evidence(incident)
        contact_list = sorted({str(item).strip() for item in contacts if str(item).strip()})
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO devices(incident_id,device_id,kind,owner_team,contacts_json,"
                    "registered_by,registered_at) VALUES(?,?,?,?,?,?,?)",
                    (incident_id, device_id, kind, owner_team, canonical_json(contact_list),
                     actor_id, self._now()),
                )
                self._audit("device", f"{incident_id}/{device_id}", "device.registered", actor_id,
                            {"kind": kind, "owner_team": owner_team})
        except sqlite3.IntegrityError as exc:
            raise Conflict("设备已登记或异常单不存在") from exc
        return {"incident_id": incident_id, "device_id": device_id, "contacts": contact_list}

    def upsert_deployment(
        self,
        actor_id: str,
        incident_id: str,
        device_id: str,
        component: str,
        version: str,
        digest: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "context.register")
        incident = self._incident_row(incident_id)
        self._require_open_for_evidence(incident)
        if len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
            raise ValidationFailed("digest 必须是 64 位十六进制 SHA-256")
        with transaction(self.connection, immediate=True):
            exists = self.connection.execute(
                "SELECT 1 FROM devices WHERE incident_id=? AND device_id=?", (incident_id, device_id)
            ).fetchone()
            if exists is None:
                raise NotFound("设备未登记")
            self.connection.execute(
                "INSERT INTO deployments(incident_id,device_id,component,version,digest,updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(incident_id,device_id,component) DO UPDATE SET "
                "version=excluded.version,digest=excluded.digest,updated_at=excluded.updated_at",
                (incident_id, device_id, component, version, digest.lower(), self._now()),
            )
            self._audit("deployment", f"{incident_id}/{device_id}/{component}",
                        "deployment.upserted", actor_id, {"version": version})
        return {"device_id": device_id, "component": component, "version": version}

    def register_ticket(
        self,
        actor_id: str,
        incident_id: str,
        ticket_id: str,
        domain: str,
        title: str,
        device_ids: Iterable[str],
        components: Iterable[str],
    ) -> dict[str, Any]:
        self._require(actor_id, "context.register")
        incident = self._incident_row(incident_id)
        self._require_open_for_evidence(incident)
        if domain not in TICKET_DOMAINS:
            raise ValidationFailed("domain 必须是 control、ai_compute 或 component_quality")
        device_list = sorted({str(item) for item in device_ids if str(item).strip()})
        component_list = sorted({str(item) for item in components if str(item).strip()})
        if not device_list and not component_list:
            raise ValidationFailed("跨域票据必须点名设备或软件部件")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO tickets(incident_id,ticket_id,domain,title,device_ids_json,"
                    "components_json,status,created_by,created_at) VALUES(?,?,?,?,?,?,'open',?,?)",
                    (incident_id, ticket_id, domain, title, canonical_json(device_list),
                     canonical_json(component_list), actor_id, self._now()),
                )
                self._audit("ticket", f"{incident_id}/{ticket_id}", "ticket.registered", actor_id,
                            {"domain": domain})
        except sqlite3.IntegrityError as exc:
            raise Conflict("票据编号冲突") from exc
        return {"ticket_id": ticket_id, "domain": domain, "status": "open"}

    def update_ticket_status(self, actor_id: str, incident_id: str, ticket_id: str, status: str) -> dict[str, Any]:
        self._require(actor_id, "context.register")
        if status not in {"open", "mitigated", "closed"}:
            raise ValidationFailed("票据状态不受支持")
        incident = self._incident_row(incident_id)
        self._require_open_for_evidence(incident)
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE tickets SET status=? WHERE incident_id=? AND ticket_id=?",
                (status, incident_id, ticket_id),
            )
            if cursor.rowcount != 1:
                raise NotFound("票据不存在")
            self._audit("ticket", f"{incident_id}/{ticket_id}", "ticket.status_changed",
                        actor_id, {"status": status})
        return {"ticket_id": ticket_id, "status": status}

    def register_safety_rule(self, actor_id: str, incident_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "context.register")
        incident = self._incident_row(incident_id)
        self._require_open_for_evidence(incident)
        rule_id = self._text(raw.get("rule_id"), "rule_id")
        title = self._text(raw.get("title"), "title")
        triggers = raw.get("event_kinds")
        if not isinstance(triggers, list) or not triggers:
            raise ValidationFailed("event_kinds 必须是非空数组")
        for trigger in triggers:
            if not isinstance(trigger, str):
                raise ValidationFailed("event_kinds 条目必须是字符串")
            if trigger.startswith(ANOMALY_TRIGGER_PREFIX):
                code = trigger[len(ANOMALY_TRIGGER_PREFIX):]
                if code not in TIMELINE_ANOMALIES:
                    raise ValidationFailed(f"未知异常触发条件: {trigger}")
            elif trigger not in EVENT_KINDS:
                raise ValidationFailed(f"未知事件类型触发条件: {trigger}")
        components = raw.get("components")
        if not isinstance(components, list) or not components or not all(isinstance(item, str) for item in components):
            raise ValidationFailed("components 必须是非空字符串数组")
        action_kind = self._text(raw.get("action_kind"), "action_kind")
        if action_kind not in ACTION_KINDS:
            raise ValidationFailed("action_kind 不受支持")
        target = self._text(raw.get("rollback_target"), "rollback_target")
        priority = raw.get("priority")
        if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 999:
            raise ValidationFailed("priority 必须是 1 到 999 的整数")
        notify_roles = raw.get("notify_roles", [])
        if not isinstance(notify_roles, list) or not all(isinstance(item, str) for item in notify_roles):
            raise ValidationFailed("notify_roles 必须是字符串数组")
        bad_roles = sorted(set(notify_roles) - set(ROLES))
        if bad_roles:
            raise ValidationFailed(f"通知角色未知: {bad_roles}")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO safety_rules(incident_id,rule_id,title,event_kinds_json,components_json,"
                    "action_kind,rollback_target,priority,notify_roles_json,active,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,1,?,?)",
                    (incident_id, rule_id, title, canonical_json(sorted(set(triggers))),
                     canonical_json(sorted(set(components))), action_kind, target, priority,
                     canonical_json(sorted(set(notify_roles))), actor_id, self._now()),
                )
                self._audit("safety_rule", f"{incident_id}/{rule_id}", "safety_rule.registered",
                            actor_id, {"action_kind": action_kind})
        except sqlite3.IntegrityError as exc:
            raise Conflict("安全规则编号冲突") from exc
        return {"rule_id": rule_id, "action_kind": action_kind, "priority": priority}

    @staticmethod
    def _text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationFailed(f"{field} 必须是非空字符串")
        return value.strip()

    # ------------------------------------------------------------- 时钟校准

    def add_calibration(self, actor_id: str, incident_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "calibration.write")
        incident = self._incident_row(incident_id)
        self._require_open_for_evidence(incident)
        item = CalibrationInput.from_dict(raw)
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT coalesce(max(version),0) AS v FROM calibrations WHERE incident_id=?",
                (incident_id,),
            ).fetchone()
            version = row["v"] + 1
            self.connection.execute(
                "INSERT INTO calibrations(incident_id,version,source_id,kind,effective_at,offset_ms,"
                "reference_at,basis,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (incident_id, version, item.source_id, item.kind, item.effective_at,
                 format(item.offset_ms, "f"), item.reference_at, item.basis, actor_id, self._now()),
            )
            self._audit("calibration", f"{incident_id}@{version}", "calibration.added", actor_id,
                        {"source_id": item.source_id, "kind": item.kind, "offset_ms": format(item.offset_ms, "f")})
        return {"incident_id": incident_id, "version": version, "source_id": item.source_id,
                "offset_ms": format(item.offset_ms, "f")}

    # ---------------------------------------------------------------- 事件

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def ingest_events(
        self,
        actor_id: str,
        incident_id: str,
        idempotency_key: str,
        raw_events: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "event.ingest")
        rows = tuple(raw_events)
        if not rows:
            raise ValidationFailed("事件数组不能为空")
        request_digest = content_digest(rows)
        scope = f"events:{incident_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        incident = self._incident_row(incident_id)
        self._require_open_for_evidence(incident)
        parsed: list[EventEnvelope] = []
        for index, raw in enumerate(rows):
            parsed.append(EventEnvelope.from_dict(raw, f"events[{index}]"))
        response: dict[str, Any] = {
            "incident_id": incident_id,
            "received": len(parsed),
            "stored_arrival_seqs": [],
            "retransmit_count": 0,
            "conflict_count": 0,
            "request_sha256": request_digest,
        }
        with transaction(self.connection, immediate=True):
            for item in parsed:
                now = self._now()
                cursor = self.connection.execute(
                    "INSERT INTO events(incident_id,source_id,sequence,source_clock,received_at,kind,"
                    "incident_ref,device_ref,content_digest,payload_json,recorded_by,recorded_at,after_revision) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (incident_id, item.source_id, item.sequence, item.source_clock, now, item.kind,
                     item.incident_ref, item.device_ref, item.content_digest,
                     canonical_json(item.payload), actor_id, now, incident["current_revision"]),
                )
                response["stored_arrival_seqs"].append(cursor.lastrowid)
                prior = self.connection.execute(
                    "SELECT content_digest FROM events WHERE incident_id=? AND source_id=? AND sequence=? "
                    "AND arrival_seq<>?",
                    (incident_id, item.source_id, item.sequence, cursor.lastrowid),
                ).fetchall()
                if prior:
                    if any(row["content_digest"] == item.content_digest for row in prior):
                        response["retransmit_count"] += 1
                    if any(row["content_digest"] != item.content_digest for row in prior):
                        response["conflict_count"] += 1
            self.connection.execute(
                "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) "
                "VALUES(?,?,?,?,?)",
                (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
            )
            self._audit("incident", incident_id, "events.ingested", actor_id, response)
        return response

    # ----------------------------------------------------------- 时间线复算

    def _load_points(self, incident_id: str) -> list[EventPoint]:
        rows = self.connection.execute(
            "SELECT arrival_seq,source_id,sequence,kind,source_clock,received_at,content_digest,device_ref "
            "FROM events WHERE incident_id=? ORDER BY arrival_seq",
            (incident_id,),
        ).fetchall()
        return [
            EventPoint(
                arrival_seq=row["arrival_seq"], source_id=row["source_id"], sequence=row["sequence"],
                kind=row["kind"], source_clock=row["source_clock"], received_at=row["received_at"],
                content_digest=row["content_digest"], device_ref=row["device_ref"],
            )
            for row in rows
        ]

    def _load_calibrations(self, incident_id: str) -> list[CalibrationPoint]:
        rows = self.connection.execute(
            "SELECT version,source_id,kind,effective_at,offset_ms,basis FROM calibrations "
            "WHERE incident_id=? ORDER BY version",
            (incident_id,),
        ).fetchall()
        return [
            CalibrationPoint(
                version=row["version"], source_id=row["source_id"], kind=row["kind"],
                effective_at=row["effective_at"], offset_ms=Decimal(row["offset_ms"]), basis=row["basis"],
            )
            for row in rows
        ]

    def current_timeline(self, incident_id: str) -> dict[str, Any]:
        """依据当前全部事件与校准版本确定性复算时间线。"""

        incident = self._incident_row(incident_id)
        return build_timeline(
            self._load_points(incident_id),
            self._load_calibrations(incident_id),
            Decimal(incident["drift_threshold_ms"]),
        )

    def _manifest(self, incident_id: str) -> dict[str, Any]:
        device_rows = self.connection.execute(
            "SELECT * FROM devices WHERE incident_id=? ORDER BY device_id", (incident_id,)
        ).fetchall()
        devices = []
        for row in device_rows:
            deployments = [
                {"component": item["component"], "version": item["version"], "digest": item["digest"]}
                for item in self.connection.execute(
                    "SELECT component,version,digest FROM deployments WHERE incident_id=? AND device_id=? "
                    "ORDER BY component",
                    (incident_id, row["device_id"]),
                ).fetchall()
            ]
            devices.append({
                "device_id": row["device_id"],
                "kind": row["kind"],
                "owner_team": row["owner_team"],
                "contacts": json.loads(row["contacts_json"]),
                "deployments": deployments,
            })
        tickets = [
            {
                "ticket_id": row["ticket_id"],
                "domain": row["domain"],
                "title": row["title"],
                "status": row["status"],
                "device_ids": json.loads(row["device_ids_json"]),
                "components": json.loads(row["components_json"]),
            }
            for row in self.connection.execute(
                "SELECT * FROM tickets WHERE incident_id=? ORDER BY ticket_id", (incident_id,)
            ).fetchall()
        ]
        rules = [
            {
                "rule_id": row["rule_id"],
                "title": row["title"],
                "event_kinds": json.loads(row["event_kinds_json"]),
                "components": json.loads(row["components_json"]),
                "action_kind": row["action_kind"],
                "rollback_target": row["rollback_target"],
                "priority": row["priority"],
                "notify_roles": json.loads(row["notify_roles_json"]),
                "active": bool(row["active"]),
            }
            for row in self.connection.execute(
                "SELECT * FROM safety_rules WHERE incident_id=? ORDER BY rule_id", (incident_id,)
            ).fetchall()
        ]
        return {"devices": devices, "tickets": tickets, "rules": rules}

    # ---------------------------------------------------------------- 封存

    def freeze_revision(self, actor_id: str, incident_id: str, expected_revision: int, rationale: str) -> dict[str, Any]:
        self._require(actor_id, "incident.freeze")
        if not rationale.strip():
            raise ValidationFailed("封存必须给出决定说明")
        incident = self._incident_row(incident_id)
        if incident["state"] not in {"collecting", "reopened"}:
            raise InvalidState("异常单不在可封存状态")
        if incident["current_revision"] != expected_revision:
            raise Conflict("修订版本已变化，请重新复算后再封存")
        points = self._load_points(incident_id)
        if not points:
            raise InvalidState("没有任何事件，不能封存")
        timeline = build_timeline(
            points,
            self._load_calibrations(incident_id),
            Decimal(incident["drift_threshold_ms"]),
        )
        manifest = self._manifest(incident_id)
        impact = derive_impact(timeline, manifest, manifest["tickets"], manifest["rules"])
        revision = expected_revision + 1
        now = self._now()
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO revision_snapshots(incident_id,revision,calibration_version,drift_threshold_ms,"
                "timeline_json,timeline_sha256,manifest_json,impact_json,notify_scope_json,rationale,"
                "created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (incident_id, revision, timeline["calibration_version"], timeline["drift_threshold_ms"],
                 canonical_json(timeline), timeline["timeline_sha256"], canonical_json(manifest),
                 canonical_json(impact), canonical_json(impact["notify_scope"]), rationale.strip(),
                 actor_id, now),
            )
            self.connection.execute(
                "UPDATE incidents SET state='frozen',current_revision=?,frozen_by=?,frozen_at=? "
                "WHERE incident_id=? AND current_revision=?",
                (revision, actor_id, now, incident_id, expected_revision),
            )
            # 新一轮封存使仍在提案中的旧计划失效；已批准计划保留为历史执行记录。
            self.connection.execute(
                "UPDATE rollback_plans SET status='cancelled',review_note='被新封存修订取代',reviewed_at=? "
                "WHERE incident_id=? AND status='proposed'",
                (now, incident_id),
            )
            self._audit("incident", incident_id, "revision.frozen", actor_id,
                        {"revision": revision, "timeline_sha256": timeline["timeline_sha256"],
                         "anomaly_count": len(timeline["anomalies"]),
                         "affected_devices": len(impact["affected_devices"]),
                         "candidate_actions": len(impact["candidate_actions"])})
        return {"incident_id": incident_id, "revision": revision,
                "timeline_sha256": timeline["timeline_sha256"], "impact": impact}

    def get_revision(self, incident_id: str, revision: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM revision_snapshots WHERE incident_id=? AND revision=?",
            (incident_id, revision),
        ).fetchone()
        if row is None:
            raise NotFound("封存修订不存在")
        return {
            "incident_id": incident_id,
            "revision": revision,
            "calibration_version": row["calibration_version"],
            "drift_threshold_ms": row["drift_threshold_ms"],
            "timeline": json.loads(row["timeline_json"]),
            "timeline_sha256": row["timeline_sha256"],
            "manifest": json.loads(row["manifest_json"]),
            "impact": json.loads(row["impact_json"]),
            "notify_scope": json.loads(row["notify_scope_json"]),
            "rationale": row["rationale"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
        }

    def list_revisions(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT revision,calibration_version,timeline_sha256,rationale,created_by,created_at "
            "FROM revision_snapshots WHERE incident_id=? ORDER BY revision",
            (incident_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------------------------------------------------------------- 复开

    def request_reopen(self, actor_id: str, incident_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "reopen.request")
        if not reason.strip():
            raise ValidationFailed("复开申请必须说明迟到证据")
        incident = self._incident_row(incident_id)
        if incident["state"] != "frozen":
            raise InvalidState("只有已封存的回放可以申请复开")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT 1 FROM reopen_requests WHERE incident_id=? AND status='pending'", (incident_id,)
            ).fetchone()
            if pending is not None:
                raise InvalidState("已有待审批的复开申请")
            cursor = self.connection.execute(
                "INSERT INTO reopen_requests(incident_id,from_revision,reason,status,requested_by,requested_at) "
                "VALUES(?,?,?,'pending',?,?)",
                (incident_id, incident["current_revision"], reason.strip(), actor_id, self._now()),
            )
            request_id = cursor.lastrowid
            self._audit("incident", incident_id, "reopen.requested", actor_id,
                        {"request_id": request_id, "from_revision": incident["current_revision"]})
        return {"request_id": request_id, "status": "pending",
                "from_revision": incident["current_revision"]}

    def review_reopen(self, actor_id: str, request_id: int, approve: bool, note: str) -> dict[str, Any]:
        self._require(actor_id, "reopen.review")
        row = self.connection.execute(
            "SELECT * FROM reopen_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise NotFound("复开申请不存在")
        if row["status"] != "pending":
            raise InvalidState("复开申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("不能审批自己提交的复开申请")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE reopen_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE request_id=? AND status='pending'",
                (status, actor_id, self._now(), note, request_id),
            )
            if approve:
                self.connection.execute(
                    "UPDATE incidents SET state='reopened' WHERE incident_id=? AND state='frozen'",
                    (row["incident_id"],),
                )
            self._audit("incident", row["incident_id"], f"reopen.{status}", actor_id,
                        {"request_id": request_id})
        return {"request_id": request_id, "status": status}

    # ------------------------------------------------------------ 回退计划

    def propose_plan(
        self, actor_id: str, incident_id: str, revision: int, rationale: str
    ) -> dict[str, Any]:
        self._require(actor_id, "plan.propose")
        if not rationale.strip():
            raise ValidationFailed("回退计划必须说明依据")
        snapshot = self._snapshot_row(incident_id, revision)
        incident = self._incident_row(incident_id)
        if incident["state"] != "frozen":
            raise InvalidState("异常单未封存，不能提出回退计划")
        if incident["current_revision"] != revision:
            raise InvalidState("只能针对最新封存修订提出计划；旧修订请先复开或查看历史")
        impact = json.loads(snapshot["impact_json"])
        candidates = impact["candidate_actions"]
        if not candidates:
            raise InvalidState("该修订没有推导出候选回退动作")
        plan_hash = hex_digest({
            "incident_id": incident_id,
            "revision": revision,
            "actions": [
                {key: action[key] for key in ("device_id", "action_kind", "target", "ordinal")}
                for action in candidates
            ],
        })
        now = self._now()
        with transaction(self.connection, immediate=True):
            duplicate = self.connection.execute(
                "SELECT 1 FROM rollback_plans WHERE incident_id=? AND revision=? AND status IN ('proposed','approved')",
                (incident_id, revision),
            ).fetchone()
            if duplicate is not None:
                raise Conflict("该修订已有待批或已批准的回退计划")
            cursor = self.connection.execute(
                "INSERT INTO rollback_plans(incident_id,revision,rationale,status,plan_sha256,"
                "proposed_by,proposed_at) VALUES(?,?,?,'proposed',?,?,?)",
                (incident_id, revision, rationale.strip(), plan_hash, actor_id, now),
            )
            plan_id = cursor.lastrowid
            for action in candidates:
                self.connection.execute(
                    "INSERT INTO rollback_actions(plan_id,incident_id,device_id,action_kind,target,"
                    "priority,rule_ids_json,ordinal,status) VALUES(?,?,?,?,?,?,?,?,'pending')",
                    (plan_id, incident_id, action["device_id"], action["action_kind"], action["target"],
                     action["priority"], canonical_json(action["rule_ids"]), action["ordinal"]),
                )
            self._audit("plan", str(plan_id), "plan.proposed", actor_id,
                        {"revision": revision, "actions": len(candidates), "plan_sha256": plan_hash})
        return self.get_plan(plan_id)

    def _snapshot_row(self, incident_id: str, revision: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM revision_snapshots WHERE incident_id=? AND revision=?",
            (incident_id, revision),
        ).fetchone()
        if row is None:
            raise NotFound("封存修订不存在")
        return row

    def review_plan(self, actor_id: str, plan_id: int, approve: bool, note: str) -> dict[str, Any]:
        self._require(actor_id, "plan.review")
        row = self.connection.execute("SELECT * FROM rollback_plans WHERE plan_id=?", (plan_id,)).fetchone()
        if row is None:
            raise NotFound("回退计划不存在")
        if row["status"] != "proposed":
            raise InvalidState("回退计划不在待批状态")
        if row["proposed_by"] == actor_id:
            raise Forbidden("提出者不能批准自己的回退计划，必须由另一名授权者确认")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE rollback_plans SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE plan_id=? AND status='proposed'",
                (status, actor_id, self._now(), note, plan_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("回退计划状态已变化")
            self._audit("plan", str(plan_id), f"plan.{status}", actor_id, {"note": note})
        return self.get_plan(plan_id)

    def cancel_plan(self, actor_id: str, plan_id: int, note: str) -> dict[str, Any]:
        self._require(actor_id, "plan.cancel")
        row = self.connection.execute("SELECT * FROM rollback_plans WHERE plan_id=?", (plan_id,)).fetchone()
        if row is None:
            raise NotFound("回退计划不存在")
        if row["proposed_by"] != actor_id:
            raise Forbidden("只有计划提出者可以撤回")
        if row["status"] != "proposed":
            raise InvalidState("只有待批计划可以撤回")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE rollback_plans SET status='cancelled',review_note=?,reviewed_at=? WHERE plan_id=?",
                (note, self._now(), plan_id),
            )
            self._audit("plan", str(plan_id), "plan.cancelled", actor_id, {"note": note})
        return self.get_plan(plan_id)

    def get_plan(self, plan_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM rollback_plans WHERE plan_id=?", (plan_id,)).fetchone()
        if row is None:
            raise NotFound("回退计划不存在")
        actions = [
            dict(item) | {"rule_ids": json.loads(item["rule_ids_json"])}
            for item in self.connection.execute(
                "SELECT * FROM rollback_actions WHERE plan_id=? ORDER BY ordinal,action_id", (plan_id,)
            ).fetchall()
        ]
        for item in actions:
            item.pop("rule_ids_json", None)
        result = dict(row)
        result["actions"] = actions
        result["device_progress"] = self._device_progress(actions)
        return result

    @staticmethod
    def _device_progress(actions: list) -> dict[str, dict[str, Any]]:
        progress: dict[str, dict[str, Any]] = {}
        for action in actions:
            item = progress.setdefault(
                action["device_id"],
                {f"count_{status}": 0 for status in ACTION_STATUSES} | {"total": 0},
            )
            item["total"] += 1
            item[f"count_{action['status']}"] += 1
        for device_id, item in progress.items():
            done = item["count_succeeded"] + item["count_skipped"]
            item["completed_fraction"] = f"{done}/{item['total']}"
            item["finished"] = done + item["count_failed"] == item["total"]
        return dict(sorted(progress.items()))

    def list_plans(self, incident_id: str, revision: int | None = None) -> list[dict[str, Any]]:
        if revision is None:
            rows = self.connection.execute(
                "SELECT plan_id FROM rollback_plans WHERE incident_id=? ORDER BY plan_id", (incident_id,)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT plan_id FROM rollback_plans WHERE incident_id=? AND revision=? ORDER BY plan_id",
                (incident_id, revision),
            ).fetchall()
        return [self.get_plan(row["plan_id"]) for row in rows]

    def device_progress(self, incident_id: str, revision: int | None = None) -> dict[str, Any]:
        """汇总每台设备在指定（默认最新）修订下的回退进度。"""

        incident = self._incident_row(incident_id)
        revision = revision or incident["current_revision"]
        plans = self.list_plans(incident_id, revision)
        active = next(
            (plan for plan in plans if plan["status"] in {"approved", "proposed"}),
            None,
        )
        chosen = active or (plans[-1] if plans else None)
        return {
            "incident_id": incident_id,
            "revision": revision,
            "plan_id": None if chosen is None else chosen["plan_id"],
            "plan_status": None if chosen is None else chosen["status"],
            "devices": {} if chosen is None else chosen["device_progress"],
            "actions": [] if chosen is None else [
                {key: action[key] for key in (
                    "device_id", "action_kind", "target", "ordinal", "status",
                    "updated_by", "updated_at", "result_note")}
                for action in chosen["actions"]
            ],
        }

    def update_action(
        self, actor_id: str, plan_id: int, action_id: int, status: str, note: str = ""
    ) -> dict[str, Any]:
        self._require(actor_id, "action.update")
        if status not in ACTION_TRANSITIONS:
            raise ValidationFailed("动作状态不受支持")
        plan = self.connection.execute("SELECT * FROM rollback_plans WHERE plan_id=?", (plan_id,)).fetchone()
        if plan is None:
            raise NotFound("回退计划不存在")
        if plan["status"] != "approved":
            raise InvalidState("回退计划未经第二名授权者批准，不能执行")
        action = self.connection.execute(
            "SELECT * FROM rollback_actions WHERE plan_id=? AND action_id=?", (plan_id, action_id)
        ).fetchone()
        if action is None:
            raise NotFound("回退动作不存在")
        allowed = ACTION_TRANSITIONS[action["status"]]
        if status not in allowed:
            raise InvalidState(f"动作不能从 {action['status']} 转为 {status}，允许: {sorted(allowed)}")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE rollback_actions SET status=?,updated_by=?,updated_at=?,result_note=? "
                "WHERE action_id=? AND status=?",
                (status, actor_id, self._now(), note, action_id, action["status"]),
            )
            if cursor.rowcount != 1:
                raise InvalidState("动作状态已被其他流程改变")
            self._audit("action", str(action_id), "action.updated", actor_id,
                        {"plan_id": plan_id, "device_id": action["device_id"], "status": status})
        return self.get_plan(plan_id)

    # ------------------------------------------------------------- 通知

    def dispatch_notification(
        self, actor_id: str, incident_id: str, revision: int, channel: str
    ) -> dict[str, Any]:
        self._require(actor_id, "notification.dispatch")
        channel = self._text(channel, "channel")
        snapshot = self._snapshot_row(incident_id, revision)
        scope = json.loads(snapshot["notify_scope_json"])
        manifest = json.loads(snapshot["manifest_json"])
        contact_set = set(scope.get("contacts", []))
        for device in manifest["devices"]:
            if device["device_id"] in {item["device_id"] for item in json.loads(snapshot["impact_json"])["affected_devices"]}:
                contact_set.update(device.get("contacts", []))
        recipients = sorted(contact_set)
        if not recipients and not scope.get("roles") and not scope.get("teams"):
            raise InvalidState("通知范围为空")
        subject = f"异常 {incident_id} 修订 {revision} 已封存并形成回退候选"
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO notifications(incident_id,revision,audience_json,recipients_json,channel,"
                "subject,rationale,created_by,created_at,dispatched_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (incident_id, revision, canonical_json(scope), canonical_json(recipients), channel,
                 subject, snapshot["rationale"], actor_id, now, now),
            )
            notification_id = cursor.lastrowid
            self._audit("notification", str(notification_id), "notification.dispatched", actor_id,
                        {"revision": revision, "channel": channel, "recipient_count": len(recipients)})
        return {"notification_id": notification_id, "revision": revision, "channel": channel,
                "audience": scope, "recipients": recipients}

    def list_notifications(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT notification_id,revision,audience_json,recipients_json,channel,subject,created_by,"
            "dispatched_at FROM notifications WHERE incident_id=? ORDER BY notification_id",
            (incident_id,),
        ).fetchall()
        return [
            dict(row) | {"audience": json.loads(row["audience_json"]),
                         "recipients": json.loads(row["recipients_json"])}
            for row in rows
        ]

    # ---------------------------------------------------------------- 关闭

    def close_incident(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        self._require(actor_id, "incident.close")
        incident = self._incident_row(incident_id)
        if incident["state"] != "frozen":
            raise InvalidState("只有已封存异常可以关闭")
        pending = self.connection.execute(
            "SELECT 1 FROM rollback_actions a JOIN rollback_plans p ON p.plan_id=a.plan_id "
            "WHERE p.incident_id=? AND p.status='approved' AND a.status IN ('pending','in_progress') LIMIT 1",
            (incident_id,),
        ).fetchone()
        if pending is not None:
            raise InvalidState("仍有已批准回退动作未执行完毕")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE incidents SET state='closed' WHERE incident_id=? AND state='frozen'",
                (incident_id,),
            )
            self._audit("incident", incident_id, "incident.closed", actor_id, {})
        return self.get_incident(incident_id)

    # ---------------------------------------------------------------- 报告

    def report(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        self._require(actor_id, "report.read")
        incident = self._incident_row(incident_id)
        timeline = self.current_timeline(incident_id)
        revisions = []
        for row in self.connection.execute(
            "SELECT revision,calibration_version,timeline_sha256,rationale,created_by,created_at,"
            "impact_json,notify_scope_json FROM revision_snapshots WHERE incident_id=? ORDER BY revision",
            (incident_id,),
        ).fetchall():
            impact = json.loads(row["impact_json"])
            revisions.append({
                "revision": row["revision"],
                "calibration_version": row["calibration_version"],
                "timeline_sha256": row["timeline_sha256"],
                "rationale": row["rationale"],
                "created_by": row["created_by"],
                "created_at": row["created_at"],
                "decision_basis": impact["decision_basis"],
                "affected_devices": impact["affected_devices"],
                "candidate_action_count": len(impact["candidate_actions"]),
                "notify_scope": json.loads(row["notify_scope_json"]),
            })
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='incident' AND entity_id=? ORDER BY event_id",
            (incident_id,),
        ).fetchall()
        return {
            "incident": incident,
            "live_timeline": timeline,
            "manifest": self._manifest(incident_id),
            "revisions": revisions,
            "plans": self.list_plans(incident_id),
            "device_progress": self.device_progress(incident_id),
            "notifications": self.list_notifications(incident_id),
            "reopen_requests": [
                dict(row) for row in self.connection.execute(
                    "SELECT request_id,from_revision,status,reason,requested_by,reviewed_by,reviewed_at "
                    "FROM reopen_requests WHERE incident_id=? ORDER BY request_id",
                    (incident_id,),
                ).fetchall()
            ],
            "audit_events": [
                dict(row) | {"payload": json.loads(row["payload_json"])} for row in events
            ],
        }
