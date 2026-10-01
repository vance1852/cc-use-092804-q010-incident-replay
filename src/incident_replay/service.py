"""现场异常回放服务的领域用例。

不变量：
- 事件只追加，后到记录永不覆盖先到记录，重复序列号直接冲突；
- 校准与时间线版本不可变，迟到证据只能产生新版本或复开申请；
- 封存结论一经写入不可修改，复开后再次封存新增一行；
- 回退方案在冻结时刻按当时主数据推导，须由冻结人之外的授权者确认后才能执行。
"""

from __future__ import annotations

import json
import sqlite3
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .clock import SystemClock, isoformat
from .impact import derive_plan
from .jsonio import canonical_json, content_digest, digest_lines
from .models import IncomingEvent, SafetyRuleInput, SourceCalibration, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .storage import initialize, transaction
from .timeline import build_timeline


ROLE_PERMISSIONS = {
    "collector": {"event.ingest", "incident.read"},
    "analyst": {
        "master.write", "calibration.publish", "incident.create", "incident.read",
        "revision.build", "conclusion.freeze", "reopen.review", "report.read",
    },
    "approver": {
        "incident.read", "plan.confirm", "plan.execute", "notification.dispatch", "report.read",
    },
    "auditor": {"incident.read", "report.read", "audit.read"},
}

CONFLICT_WINDOW_MS = 5


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
        if role not in ROLE_PERMISSIONS:
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

    def register_source(self, actor_id: str, source_id: str, domain: str, label: str) -> dict[str, Any]:
        self._require(actor_id, "master.write")
        if domain not in {"control", "ai", "component"}:
            raise ValidationFailed("domain 必须是 control、ai 或 component")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO sources(source_id,domain,label,registered_by,registered_at) VALUES(?,?,?,?,?)",
                    (source_id, domain, label, actor_id, self._now()),
                )
                self._audit("source", source_id, "source.registered", actor_id, {"domain": domain})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"来源已存在: {source_id}") from exc
        return {"source_id": source_id, "domain": domain, "label": label}

    # ------------------------------------------------------------ 时钟校准

    def publish_calibration(
        self, actor_id: str, basis: str, raw_entries: Iterable[Mapping[str, Any]]
    ) -> dict[str, Any]:
        self._require(actor_id, "calibration.publish")
        entries: list[SourceCalibration] = []
        seen: set[str] = set()
        for index, raw in enumerate(raw_entries):
            try:
                entry = SourceCalibration.from_dict(raw, f"calibration.entries[{index}]")
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if entry.source_id in seen:
                raise ValidationFailed(f"校准来源重复: {entry.source_id}")
            seen.add(entry.source_id)
            entries.append(entry)
        if not entries:
            raise ValidationFailed("校准条目不能为空")
        normalized = [entry.normalized() for entry in entries]
        digest = content_digest({"basis": basis, "entries": normalized})
        with transaction(self.connection, immediate=True):
            for entry in entries:
                if self.connection.execute(
                    "SELECT 1 FROM sources WHERE source_id=?", (entry.source_id,)
                ).fetchone() is None:
                    raise NotFound(f"来源未登记: {entry.source_id}")
            cursor = self.connection.execute(
                "INSERT INTO calibration_versions(basis,content_sha256,published_by,published_at) "
                "VALUES(?,?,?,?)",
                (basis, digest, actor_id, self._now()),
            )
            version = cursor.lastrowid
            for entry in entries:
                self.connection.execute(
                    "INSERT INTO calibration_entries(version,source_id,drift_ppm,anchor_source,anchor_reference) "
                    "VALUES(?,?,?,?,?)",
                    (
                        version, entry.source_id, format(entry.drift_ppm, "f"),
                        entry.anchor_source, entry.anchor_reference,
                    ),
                )
            self._audit("calibration", str(version), "calibration.published", actor_id, {
                "version": version, "sha256": digest, "sources": sorted(seen),
            })
        return {"version": version, "basis": basis, "entries": normalized, "sha256": digest}

    def _calibrations(self, version: int) -> dict[str, SourceCalibration]:
        rows = self.connection.execute(
            "SELECT * FROM calibration_entries WHERE version=?", (version,)
        ).fetchall()
        if not rows and self.connection.execute(
            "SELECT 1 FROM calibration_versions WHERE version=?", (version,)
        ).fetchone() is None:
            raise NotFound(f"校准版本不存在: {version}")
        return {
            row["source_id"]: SourceCalibration(
                source_id=row["source_id"],
                drift_ppm=Decimal(row["drift_ppm"]),
                anchor_source=row["anchor_source"],
                anchor_reference=row["anchor_reference"],
            )
            for row in rows
        }

    # ------------------------------------------------------------ 现场主数据

    def register_combo(self, actor_id: str, combo_id: str, domain: str, components: list[str]) -> dict[str, Any]:
        self._require(actor_id, "master.write")
        clean = sorted({str(item).strip() for item in components if str(item).strip()})
        if not clean:
            raise ValidationFailed("软件组合的组件列表不能为空")
        digest = content_digest({"combo_id": combo_id, "domain": domain, "components": clean})
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO software_combos(combo_id,domain,components_json,content_sha256,"
                    "registered_by,created_at) VALUES(?,?,?,?,?,?)",
                    (combo_id, domain, canonical_json(clean), digest, actor_id, self._now()),
                )
                self._audit("combo", combo_id, "combo.registered", actor_id, {"domain": domain})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"软件组合已存在: {combo_id}") from exc
        return {"combo_id": combo_id, "domain": domain, "components": clean}

    def register_device(self, actor_id: str, device_id: str, domain: str, combo_id: str | None) -> dict[str, Any]:
        self._require(actor_id, "master.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO devices(device_id,domain,combo_id,registered_by,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (device_id, domain, combo_id, actor_id, self._now()),
                )
                self._audit("device", device_id, "device.registered", actor_id, {
                    "domain": domain, "combo_id": combo_id,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("设备编号冲突或软件组合不存在") from exc
        return {"device_id": device_id, "domain": domain, "combo_id": combo_id}

    def register_ticket(
        self,
        actor_id: str,
        ticket_id: str,
        summary: str,
        domains: list[str],
        combo_ids: list[str],
        device_ids: list[str],
    ) -> dict[str, Any]:
        self._require(actor_id, "master.write")
        domains_v = sorted({str(item) for item in domains})
        combo_ids_v = sorted({str(item) for item in combo_ids})
        device_ids_v = sorted({str(item) for item in device_ids})
        digest = content_digest({
            "ticket_id": ticket_id, "summary": summary, "domains": domains_v,
            "combo_ids": combo_ids_v, "device_ids": device_ids_v,
        })
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO tickets(ticket_id,summary,domains_json,combo_ids_json,device_ids_json,"
                    "content_sha256,registered_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        ticket_id, summary, canonical_json(domains_v), canonical_json(combo_ids_v),
                        canonical_json(device_ids_v), digest, actor_id, self._now(),
                    ),
                )
                self._audit("ticket", ticket_id, "ticket.registered", actor_id, {
                    "domains": domains_v, "device_ids": device_ids_v,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"跨域票据已存在: {ticket_id}") from exc
        return {
            "ticket_id": ticket_id, "summary": summary, "domains": domains_v,
            "combo_ids": combo_ids_v, "device_ids": device_ids_v,
        }

    def register_safety_rule(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "master.write")
        try:
            rule = SafetyRuleInput.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        normalized = rule.normalized()
        digest = content_digest(normalized)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO safety_rules(rule_id,version,event_types_json,domains_json,"
                    "components_json,action,notify_roles_json,content_sha256,registered_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        rule.rule_id, rule.version,
                        canonical_json(normalized["event_types"]),
                        canonical_json(normalized["domains"]),
                        canonical_json(normalized["components"]),
                        rule.action,
                        canonical_json(normalized["notify_roles"]),
                        digest, actor_id, self._now(),
                    ),
                )
                self._audit("rule", f"{rule.rule_id}v{rule.version}", "rule.registered", actor_id, {
                    "sha256": digest,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("安全规则版本已存在") from exc
        return normalized | {"sha256": digest}

    # ------------------------------------------------------------ 案卷与事件

    def create_incident(self, actor_id: str, incident_id: str, title: str) -> dict[str, Any]:
        self._require(actor_id, "incident.create")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO incidents(incident_id,title,state,created_by,created_at) VALUES(?,?,'open',?,?)",
                    (incident_id, title, actor_id, self._now()),
                )
                self._audit("incident", incident_id, "incident.created", actor_id, {"title": title})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"案卷已存在: {incident_id}") from exc
        return self.get_incident(incident_id)

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise NotFound("案卷不存在")
        return dict(row)

    def _parse_events(self, raw_events: Iterable[Mapping[str, Any]]) -> list[IncomingEvent]:
        parsed: list[IncomingEvent] = []
        for index, raw in enumerate(raw_events):
            try:
                parsed.append(IncomingEvent.from_dict(raw, f"events[{index}]"))
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
        return parsed

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

    def _insert_events(
        self,
        incident_id: str,
        events: list[IncomingEvent],
        actor_id: str,
        state: str,
        reopen_request_id: int | None,
    ) -> int:
        """在已开启的事务里追加事件；重复序列号冲突时由调用方回滚。"""

        rank_row = self.connection.execute(
            "SELECT COALESCE(MAX(arrival_rank), 0) + 1 AS next_rank FROM events WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
        next_rank = int(rank_row["next_rank"])
        inserted = 0
        for event in events:
            self.connection.execute(
                "INSERT INTO events(incident_id,source_id,sequence,source_clock,event_type,content_json,"
                "content_sha256,arrival_rank,state,reopen_request_id,ingested_by,ingested_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    incident_id, event.source_id, event.sequence, event.source_clock, event.event_type,
                    canonical_json(event.content), event.content_sha256, next_rank + inserted, state,
                    reopen_request_id, actor_id, self._now(),
                ),
            )
            inserted += 1
        return inserted

    def ingest_events(
        self,
        actor_id: str,
        incident_id: str,
        idempotency_key: str,
        raw_events: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """在案卷开启时接收事件，严格保留到达顺序。"""

        self._require(actor_id, "event.ingest")
        events = self._parse_events(raw_events)
        if not events:
            raise ValidationFailed("事件数组不能为空")
        request_digest = digest_lines([event.content for event in events])
        scope = f"events:{incident_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        incident = self.get_incident(incident_id)
        if incident["state"] not in {"open", "reopened"}:
            raise InvalidState("案卷已封存，迟到证据必须通过复开申请提交，不能直接写入")
        response = {"incident_id": incident_id, "inserted": len(events), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                inserted = self._insert_events(incident_id, events, actor_id, "active", None)
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("incident", incident_id, "events.ingested", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("(案卷,来源,序列号) 重复：后到记录不能覆盖先到记录") from exc
        return response

    def submit_late_evidence(
        self,
        actor_id: str,
        incident_id: str,
        reason: str,
        raw_events: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """封存后提交迟到证据：生成复开申请并暂存证据，绝不改写封存结论。"""

        self._require(actor_id, "event.ingest")
        events = self._parse_events(raw_events)
        if not events:
            raise ValidationFailed("迟到证据不能为空")
        incident = self.get_incident(incident_id)
        if incident["state"] != "sealed":
            raise InvalidState("只有已封存案卷才需要走迟到证据复开流程")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO reopen_requests(incident_id,status,reason,requested_by,requested_at) "
                    "VALUES(?, 'pending', ?,?,?)",
                    (incident_id, reason, actor_id, self._now()),
                )
                request_id = cursor.lastrowid
                inserted = self._insert_events(incident_id, events, actor_id, "staged", request_id)
                self._audit("incident", incident_id, "reopen.requested", actor_id, {
                    "request_id": request_id, "staged": inserted, "reason": reason,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("迟到证据与既有记录的(来源,序列号)冲突，不能覆盖已封存证据") from exc
        return {"request_id": request_id, "status": "pending", "staged": inserted}

    def review_reopen(
        self, actor_id: str, request_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "reopen.review")
        row = self.connection.execute(
            "SELECT * FROM reopen_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise NotFound("复开申请不存在")
        if row["status"] != "pending":
            raise InvalidState("复开申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("调查负责人不能审批自己提交的复开申请")
        incident = self.get_incident(row["incident_id"])
        if incident["state"] != "sealed":
            raise InvalidState("案卷未处于封存状态")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            staged = self.connection.execute(
                "SELECT count(*) AS c FROM events WHERE reopen_request_id=? AND state='staged'",
                (request_id,),
            ).fetchone()["c"]
            self.connection.execute(
                "UPDATE reopen_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE request_id=? AND status='pending'",
                (status, actor_id, self._now(), note, request_id),
            )
            if approve:
                self.connection.execute(
                    "UPDATE events SET state='active' WHERE reopen_request_id=? AND state='staged'",
                    (request_id,),
                )
                self.connection.execute(
                    "UPDATE incidents SET state='reopened' WHERE incident_id=? AND state='sealed'",
                    (row["incident_id"],),
                )
            else:
                self.connection.execute(
                    "UPDATE events SET state='rejected_late' WHERE reopen_request_id=? AND state='staged'",
                    (request_id,),
                )
            self._audit("incident", row["incident_id"], f"reopen.{status}", actor_id, {
                "request_id": request_id, "note": note, "activated": staged if approve else 0,
            })
        return {"request_id": request_id, "status": status}

    # ------------------------------------------------------------ 时间线版本

    def _active_event_rows(self, incident_id: str) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT e.*, s.domain FROM events e JOIN sources s ON s.source_id=e.source_id "
            "WHERE e.incident_id=? AND e.state='active' ORDER BY e.arrival_rank",
            (incident_id,),
        ).fetchall()

    @staticmethod
    def _row_to_timeline_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "record_id": row["record_id"],
            "source_id": row["source_id"],
            "sequence": row["sequence"],
            "source_clock": row["source_clock"],
            "event_type": row["event_type"],
            "content": json.loads(row["content_json"]),
            "content_sha256": row["content_sha256"],
            "arrival_rank": row["arrival_rank"],
        }

    def _snapshot(self, incident_id: str, calibration_version: int, revision_no: int) -> dict[str, Any]:
        rows = self._active_event_rows(incident_id)
        calibrations = self._calibrations(calibration_version)
        records = [self._row_to_timeline_record(row) for row in rows]
        timeline = build_timeline(records, calibrations, calibration_version, conflict_window_ms=CONFLICT_WINDOW_MS)
        domain_by_source = {row["source_id"]: row["domain"] for row in rows}

        def enriched(order) -> list[dict[str, Any]]:
            return [
                {
                    "record_id": event.record_id,
                    "source_id": event.source_id,
                    "domain": domain_by_source.get(event.source_id),
                    "sequence": event.sequence,
                    "source_clock": event.source_clock,
                    "reference_clock": event.reference_clock,
                    "event_type": event.event_type,
                    "content": event.content,
                    "content_sha256": event.content_sha256,
                    "arrival_rank": event.arrival_rank,
                    "calibration_status": event.calibration_status,
                }
                for event in order
            ]

        return {
            "incident_id": incident_id,
            "revision_no": revision_no,
            "calibration_version": calibration_version,
            "arrival_order": enriched(timeline.arrival_order),
            "calibrated_order": enriched(timeline.calibrated_order),
            "annotations": [
                {
                    "kind": item.kind,
                    "severity": item.severity,
                    "source_id": item.source_id,
                    "detail": item.detail,
                    "record_ids": list(item.record_ids),
                }
                for item in timeline.annotations
            ],
        }

    def build_revision(self, actor_id: str, incident_id: str, calibration_version: int) -> dict[str, Any]:
        self._require(actor_id, "revision.build")
        incident = self.get_incident(incident_id)
        if incident["state"] not in {"open", "reopened"}:
            raise InvalidState("只有未封存的案卷可以构建回放版本")
        with transaction(self.connection, immediate=True):
            next_no_row = self.connection.execute(
                "SELECT COALESCE(MAX(revision_no), 0) + 1 AS next_no FROM incident_revisions WHERE incident_id=?",
                (incident_id,),
            ).fetchone()
            revision_no = int(next_no_row["next_no"])
            snapshot = self._snapshot(incident_id, calibration_version, revision_no)
            snapshot_digest = content_digest(snapshot)
            cursor = self.connection.execute(
                "INSERT INTO incident_revisions(incident_id,revision_no,calibration_version,snapshot_json,"
                "timeline_sha256,built_by,built_at) VALUES(?,?,?,?,?,?,?)",
                (
                    incident_id, revision_no, calibration_version, canonical_json(snapshot),
                    snapshot_digest, actor_id, self._now(),
                ),
            )
            revision_id = cursor.lastrowid
            self.connection.execute(
                "UPDATE incidents SET current_revision_no=? WHERE incident_id=?",
                (revision_no, incident_id),
            )
            self._audit("incident", incident_id, "revision.built", actor_id, {
                "revision_no": revision_no,
                "calibration_version": calibration_version,
                "timeline_sha256": snapshot_digest,
                "annotations": len(snapshot["annotations"]),
            })
        return {
            "revision_id": revision_id,
            "revision_no": revision_no,
            "calibration_version": calibration_version,
            "timeline_sha256": snapshot_digest,
            "snapshot": snapshot,
        }

    def get_revision(self, incident_id: str, revision_no: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM incident_revisions WHERE incident_id=? AND revision_no=?",
            (incident_id, revision_no),
        ).fetchone()
        if row is None:
            raise NotFound("回放版本不存在")
        return {
            "revision_id": row["revision_id"],
            "incident_id": row["incident_id"],
            "revision_no": row["revision_no"],
            "calibration_version": row["calibration_version"],
            "timeline_sha256": row["timeline_sha256"],
            "built_by": row["built_by"],
            "built_at": row["built_at"],
            "snapshot": json.loads(row["snapshot_json"]),
        }

    def replay_revision(self, incident_id: str, revision_no: int) -> dict[str, Any]:
        """用版本内记录与不可变校准重新推导时间线，校验与封存快照是否一致。"""

        revision = self.get_revision(incident_id, revision_no)
        snapshot = revision["snapshot"]
        record_ids = [item["record_id"] for item in snapshot["arrival_order"]]
        placeholders = ",".join("?" for _ in record_ids)
        rows = self.connection.execute(
            f"SELECT e.*, s.domain FROM events e JOIN sources s ON s.source_id=e.source_id "
            f"WHERE e.record_id IN ({placeholders})",
            record_ids,
        ).fetchall()
        records = [self._row_to_timeline_record(row) for row in rows]
        calibrations = self._calibrations(revision["calibration_version"])
        timeline = build_timeline(
            records, calibrations, revision["calibration_version"], conflict_window_ms=CONFLICT_WINDOW_MS
        )
        # 封存快照比引擎输出多出 incident_id/revision_no 与来源域，剥离后应与复算结果完全一致；
        # 封存时写入的 timeline_sha256 是整个快照的摘要，也必须逐字节吻合。
        stored_inner = {
            "calibration_version": snapshot["calibration_version"],
            "arrival_order": [
                {key: value for key, value in item.items() if key != "domain"}
                for item in snapshot["arrival_order"]
            ],
            "calibrated_order": [
                {key: value for key, value in item.items() if key != "domain"}
                for item in snapshot["calibrated_order"]
            ],
            "annotations": snapshot["annotations"],
        }
        snapshot_digest = content_digest(snapshot)
        return {
            "revision_no": revision_no,
            "stored_timeline_sha256": revision["timeline_sha256"],
            "recomputed_timeline_sha256": timeline.timeline_sha256,
            "stored_timeline_inner_sha256": content_digest(stored_inner),
            "snapshot_sha256": snapshot_digest,
            "timeline_matches": timeline.timeline_sha256 == content_digest(stored_inner),
            "snapshot_untampered": snapshot_digest == revision["timeline_sha256"],
            "record_ids": record_ids,
        }

    # ------------------------------------------------------------ 封存与回退

    def _master_snapshot(self) -> dict[str, Any]:
        combos = [
            {
                "combo_id": row["combo_id"],
                "domain": row["domain"],
                "components": json.loads(row["components_json"]),
            }
            for row in self.connection.execute("SELECT * FROM software_combos ORDER BY combo_id")
        ]
        devices = [
            {"device_id": row["device_id"], "domain": row["domain"], "combo_id": row["combo_id"]}
            for row in self.connection.execute("SELECT * FROM devices ORDER BY device_id")
        ]
        tickets = [
            {
                "ticket_id": row["ticket_id"],
                "summary": row["summary"],
                "domains": json.loads(row["domains_json"]),
                "combo_ids": json.loads(row["combo_ids_json"]),
                "device_ids": json.loads(row["device_ids_json"]),
            }
            for row in self.connection.execute("SELECT * FROM tickets ORDER BY ticket_id")
        ]
        rules = [
            {
                "rule_id": row["rule_id"],
                "version": row["version"],
                "event_types": json.loads(row["event_types_json"]),
                "domains": json.loads(row["domains_json"]),
                "components": json.loads(row["components_json"]),
                "action": row["action"],
                "notify_roles": json.loads(row["notify_roles_json"]),
            }
            for row in self.connection.execute("SELECT * FROM safety_rules ORDER BY rule_id, version")
        ]
        return {"combos": combos, "devices": devices, "tickets": tickets, "rules": rules}

    def freeze_conclusion(
        self,
        actor_id: str,
        incident_id: str,
        revision_no: int,
        trigger_record_ids: list[int],
        decision_basis: str,
        rationale: str,
        conflict_acknowledged: bool = False,
    ) -> dict[str, Any]:
        self._require(actor_id, "conclusion.freeze")
        if decision_basis not in {"arrival_order", "calibrated_order"}:
            raise ValidationFailed("决定依据必须是 arrival_order 或 calibrated_order")
        incident = self.get_incident(incident_id)
        if incident["state"] not in {"open", "reopened"}:
            raise InvalidState("案卷不在可封存状态")
        if incident["current_revision_no"] != revision_no:
            raise InvalidState("只能封存当前回放版本；新证据请先构建新版本")
        revision = self.get_revision(incident_id, revision_no)
        snapshot = revision["snapshot"]
        valid_ids = {item["record_id"] for item in snapshot["arrival_order"]}
        trigger_ids = sorted({int(value) for value in trigger_record_ids})
        if not trigger_ids:
            raise ValidationFailed("至少指定一条触发记录")
        unknown = sorted(set(trigger_ids) - valid_ids)
        if unknown:
            raise ValidationFailed(f"触发记录不属于本版本: {unknown}")
        # 冲突（哪怕只是窗口内的顺序歧义）与严重缺口都必须显式确认；漂移仅提示不阻断。
        blocking = [
            item for item in snapshot["annotations"]
            if item["severity"] == "critical" or item["kind"] == "conflict"
        ]
        if blocking and not conflict_acknowledged:
            raise InvalidState("存在冲突或严重缺口标注，必须显式确认后才能封存")
        master = self._master_snapshot()
        plan = derive_plan(snapshot, trigger_ids, master["combos"], master["devices"],
                           master["tickets"], master["rules"])
        basis = {
            "master_snapshot": master,
            "trigger_record_ids": trigger_ids,
            "matched_rules": plan["matched_rules"],
        }
        plan_digest = content_digest({"basis": basis, "plan": plan})
        with transaction(self.connection, immediate=True):
            if self.connection.execute(
                "SELECT 1 FROM conclusions WHERE incident_id=? AND revision_no=?",
                (incident_id, revision_no),
            ).fetchone() is not None:
                raise InvalidState("该版本已经封存；新证据只能复开后形成新版本")
            self.connection.execute(
                "INSERT INTO conclusions(incident_id,revision_no,timeline_sha256,"
                "trigger_record_ids_json,decision_basis,rationale,frozen_by,frozen_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    incident_id, revision_no, revision["timeline_sha256"],
                    canonical_json(trigger_ids), decision_basis, rationale, actor_id, self._now(),
                ),
            )
            plan_cursor = self.connection.execute(
                "INSERT INTO rollback_plans(incident_id,revision_no,status,basis_json,plan_sha256,"
                "created_by,created_at) VALUES(?,?,'proposed',?,?,?,?)",
                (incident_id, revision_no, canonical_json(basis), plan_digest, actor_id, self._now()),
            )
            plan_id = plan_cursor.lastrowid
            for device in plan["devices"]:
                self.connection.execute(
                    "INSERT INTO plan_devices(plan_id,device_id,domain,current_combo_id,reasons_json,"
                    "candidate_actions_json) VALUES(?,?,?,?,?,?)",
                    (
                        plan_id, device["device_id"], device["domain"], device["current_combo_id"],
                        canonical_json(device["reasons"]),
                        canonical_json(device["candidate_actions"]),
                    ),
                )
            for role, matched in plan["notifications"].items():
                self.connection.execute(
                    "INSERT INTO notifications(incident_id,revision_no,role,reason,status) "
                    "VALUES(?,?,?,?,'pending')",
                    (
                        incident_id, revision_no, role,
                        f"按 {', '.join(matched)} 需要通知角色 {role}",
                    ),
                )
            self.connection.execute(
                "UPDATE incidents SET state='sealed',sealed_by=?,sealed_at=? WHERE incident_id=?",
                (actor_id, self._now(), incident_id),
            )
            self._audit("incident", incident_id, "conclusion.frozen", actor_id, {
                "revision_no": revision_no,
                "timeline_sha256": revision["timeline_sha256"],
                "decision_basis": decision_basis,
                "trigger_record_ids": trigger_ids,
                "affected_devices": [item["device_id"] for item in plan["devices"]],
                "plan_sha256": plan_digest,
            })
        return self.get_plan(incident_id, revision_no)

    def get_conclusion(self, incident_id: str) -> dict[str, Any]:
        incident = self.get_incident(incident_id)
        rows = self.connection.execute(
            "SELECT * FROM conclusions WHERE incident_id=? ORDER BY revision_no", (incident_id,)
        ).fetchall()
        if not rows:
            raise NotFound("案卷尚无封存结论")
        return {
            "incident_id": incident_id,
            "current_revision_no": incident["current_revision_no"],
            "conclusions": [
                {
                    "revision_no": row["revision_no"],
                    "timeline_sha256": row["timeline_sha256"],
                    "trigger_record_ids": json.loads(row["trigger_record_ids_json"]),
                    "decision_basis": row["decision_basis"],
                    "rationale": row["rationale"],
                    "frozen_by": row["frozen_by"],
                    "frozen_at": row["frozen_at"],
                }
                for row in rows
            ],
        }

    def get_plan(self, incident_id: str, revision_no: int | None = None) -> dict[str, Any]:
        incident = self.get_incident(incident_id)
        revision_no = revision_no or incident["current_revision_no"]
        plan_row = self.connection.execute(
            "SELECT * FROM rollback_plans WHERE incident_id=? AND revision_no=?",
            (incident_id, revision_no),
        ).fetchone()
        if plan_row is None:
            raise NotFound("该版本没有回退方案")
        device_rows = self.connection.execute(
            "SELECT * FROM plan_devices WHERE plan_id=? ORDER BY device_id", (plan_row["plan_id"],)
        ).fetchall()
        notifications = self.connection.execute(
            "SELECT role,reason,status,notified_by,notified_at FROM notifications "
            "WHERE incident_id=? AND revision_no=? ORDER BY role",
            (incident_id, revision_no),
        ).fetchall()
        progress = {
            "pending": 0, "executing": 0, "succeeded": 0, "failed": 0,
        }
        devices = []
        for row in device_rows:
            progress[row["exec_status"]] += 1
            devices.append({
                "device_id": row["device_id"],
                "domain": row["domain"],
                "current_combo_id": row["current_combo_id"],
                "reasons": json.loads(row["reasons_json"]),
                "candidate_actions": json.loads(row["candidate_actions_json"]),
                "selected_action": json.loads(row["selected_action"]) if row["selected_action"] else None,
                "exec_status": row["exec_status"],
                "executed_by": row["executed_by"],
                "executed_at": row["executed_at"],
                "result_note": row["result_note"],
            })
        return {
            "incident_id": incident_id,
            "revision_no": revision_no,
            "plan_id": plan_row["plan_id"],
            "status": plan_row["status"],
            "plan_sha256": plan_row["plan_sha256"],
            "created_by": plan_row["created_by"],
            "created_at": plan_row["created_at"],
            "confirmed_by": plan_row["confirmed_by"],
            "confirmed_at": plan_row["confirmed_at"],
            "devices": devices,
            "progress": progress,
            "notifications": [dict(row) for row in notifications],
        }

    def confirm_plan(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        self._require(actor_id, "plan.confirm")
        incident = self.get_incident(incident_id)
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM rollback_plans WHERE incident_id=? AND revision_no=?",
                (incident_id, incident["current_revision_no"]),
            ).fetchone()
            if row is None:
                raise NotFound("当前版本没有回退方案")
            if row["status"] != "proposed":
                raise InvalidState("方案已确认或已开始执行")
            frozen = self.connection.execute(
                "SELECT frozen_by FROM conclusions WHERE incident_id=? AND revision_no=?",
                (incident_id, incident["current_revision_no"]),
            ).fetchone()
            if frozen is not None and frozen["frozen_by"] == actor_id:
                raise Forbidden("回退方案必须由冻结人之外的另一名授权者确认")
            self.connection.execute(
                "UPDATE rollback_plans SET status='confirmed',confirmed_by=?,confirmed_at=? WHERE plan_id=?",
                (actor_id, self._now(), row["plan_id"]),
            )
            self._audit("plan", str(row["plan_id"]), "plan.confirmed", actor_id, {
                "incident_id": incident_id, "revision_no": incident["current_revision_no"],
            })
        return self.get_plan(incident_id)

    def _device_row(self, plan_id: int, device_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM plan_devices WHERE plan_id=? AND device_id=?", (plan_id, device_id)
        ).fetchone()
        if row is None:
            raise NotFound("设备不在回退方案中")
        return row

    def execute_device_action(
        self, actor_id: str, incident_id: str, device_id: str, action: Mapping[str, Any], note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "plan.execute")
        incident = self.get_incident(incident_id)
        with transaction(self.connection, immediate=True):
            plan = self.connection.execute(
                "SELECT * FROM rollback_plans WHERE incident_id=? AND revision_no=?",
                (incident_id, incident["current_revision_no"]),
            ).fetchone()
            if plan is None:
                raise NotFound("当前版本没有回退方案")
            if plan["status"] not in {"confirmed", "executing"}:
                raise InvalidState("方案未经另一名授权者确认，禁止执行")
            device = self._device_row(plan["plan_id"], device_id)
            if device["exec_status"] not in {"pending", "failed"}:
                raise InvalidState(f"设备当前状态 {device['exec_status']} 不能执行")
            candidates = json.loads(device["candidate_actions_json"])
            if action not in candidates:
                raise ValidationFailed("只能执行推导产生的候选动作，不能临时编造")
            self.connection.execute(
                "UPDATE plan_devices SET exec_status='executing',selected_action=? WHERE plan_device_id=?",
                (canonical_json(action), device["plan_device_id"]),
            )
            self.connection.execute(
                "UPDATE plan_devices SET exec_status='succeeded',executed_by=?,executed_at=?,"
                "result_note=? WHERE plan_device_id=?",
                (actor_id, self._now(), note, device["plan_device_id"]),
            )
            self._audit("device", device_id, "device.rollback_succeeded", actor_id, {
                "incident_id": incident_id, "action": action,
            })
            self._refresh_plan_state(plan["plan_id"])
        return self.get_plan(incident_id)

    def fail_device_action(
        self, actor_id: str, incident_id: str, device_id: str, action: Mapping[str, Any], error: str
    ) -> dict[str, Any]:
        self._require(actor_id, "plan.execute")
        incident = self.get_incident(incident_id)
        with transaction(self.connection, immediate=True):
            plan = self.connection.execute(
                "SELECT * FROM rollback_plans WHERE incident_id=? AND revision_no=?",
                (incident_id, incident["current_revision_no"]),
            ).fetchone()
            if plan is None or plan["status"] not in {"confirmed", "executing"}:
                raise InvalidState("方案未经确认，不能登记执行")
            device = self._device_row(plan["plan_id"], device_id)
            if device["exec_status"] not in {"pending", "executing"}:
                raise InvalidState(f"设备当前状态 {device['exec_status']} 不能登记失败")
            candidates = json.loads(device["candidate_actions_json"])
            if action not in candidates:
                raise ValidationFailed("失败动作也必须属于候选动作集合")
            self.connection.execute(
                "UPDATE plan_devices SET exec_status='failed',selected_action=COALESCE(selected_action,?),"
                "executed_by=?,executed_at=?,result_note=? WHERE plan_device_id=?",
                (canonical_json(action), actor_id, self._now(), error, device["plan_device_id"]),
            )
            self._audit("device", device_id, "device.rollback_failed", actor_id, {
                "incident_id": incident_id, "action": action, "error": error,
            })
            self._refresh_plan_state(plan["plan_id"])
        return self.get_plan(incident_id)

    def _refresh_plan_state(self, plan_id: int) -> None:
        statuses = [
            row["exec_status"]
            for row in self.connection.execute(
                "SELECT exec_status FROM plan_devices WHERE plan_id=?", (plan_id,)
            ).fetchall()
        ]
        if statuses and all(status == "succeeded" for status in statuses):
            new_state = "completed"
        elif any(status in {"executing", "succeeded", "failed"} for status in statuses):
            new_state = "executing"
        else:
            new_state = "confirmed"
        self.connection.execute(
            "UPDATE rollback_plans SET status=? WHERE plan_id=? AND status IN ('confirmed','executing','completed')",
            (new_state, plan_id),
        )

    def mark_notified(self, actor_id: str, incident_id: str, role: str) -> dict[str, Any]:
        self._require(actor_id, "notification.dispatch")
        incident = self.get_incident(incident_id)
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE notifications SET status='notified',notified_by=?,notified_at=? "
                "WHERE incident_id=? AND revision_no=? AND role=? AND status='pending'",
                (actor_id, self._now(), incident_id, incident["current_revision_no"], role),
            )
            if cursor.rowcount != 1:
                raise InvalidState("没有待发送的该角色通知")
            self._audit("notification", f"{incident_id}:{role}", "notification.dispatched", actor_id, {
                "revision_no": incident["current_revision_no"],
            })
        return self.get_plan(incident_id)

    # ------------------------------------------------------------ 报告

    def report(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        self._require(actor_id, "report.read")
        incident = self.get_incident(incident_id)
        revisions = self.connection.execute(
            "SELECT revision_no,calibration_version,timeline_sha256,built_by,built_at "
            "FROM incident_revisions WHERE incident_id=? ORDER BY revision_no",
            (incident_id,),
        ).fetchall()
        plans = self.connection.execute(
            "SELECT revision_no,status,plan_sha256,created_by,confirmed_by,confirmed_at "
            "FROM rollback_plans WHERE incident_id=? ORDER BY revision_no",
            (incident_id,),
        ).fetchall()
        plan_details = []
        for plan in plans:
            devices = self.connection.execute(
                "SELECT device_id,exec_status,selected_action,executed_by,executed_at,result_note "
                "FROM plan_devices pd JOIN rollback_plans rp ON rp.plan_id=pd.plan_id "
                "WHERE rp.incident_id=? AND rp.revision_no=? ORDER BY device_id",
                (incident_id, plan["revision_no"]),
            ).fetchall()
            notifications = self.connection.execute(
                "SELECT role,reason,status,notified_by,notified_at FROM notifications "
                "WHERE incident_id=? AND revision_no=? ORDER BY role",
                (incident_id, plan["revision_no"]),
            ).fetchall()
            plan_details.append({
                "revision_no": plan["revision_no"],
                "status": plan["status"],
                "plan_sha256": plan["plan_sha256"],
                "created_by": plan["created_by"],
                "confirmed_by": plan["confirmed_by"],
                "confirmed_at": plan["confirmed_at"],
                "devices": [dict(row) for row in devices],
                "notifications": [dict(row) for row in notifications],
            })
        reopen = self.connection.execute(
            "SELECT request_id,status,reason,requested_by,requested_at,reviewed_by,reviewed_at,review_note "
            "FROM reopen_requests WHERE incident_id=? ORDER BY request_id",
            (incident_id,),
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='incident' AND entity_id=? ORDER BY event_id",
            (incident_id,),
        ).fetchall()
        return {
            "incident": incident,
            "revisions": [dict(row) for row in revisions],
            "plans": plan_details,
            "reopen_requests": [dict(row) for row in reopen],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }
