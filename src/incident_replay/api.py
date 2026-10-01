"""无第三方依赖的 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import ServiceError, ValidationFailed
from .service import ReplayService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    """将 HTTP 路由映射到领域服务，便于无网络单元测试。"""

    def __init__(self, service: ReplayService) -> None:
        self.service = service

    @staticmethod
    def _actor(headers: Mapping[str, str]) -> str:
        actor = headers.get("x-actor-id", "").strip()
        if not actor:
            raise ValidationFailed("缺少 X-Actor-Id")
        return actor

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    def handle(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            actor = lambda: self._actor(normalized_headers)

            if method == "POST" and path == "/users":
                result = self.service.create_user(
                    payload["user_id"], payload["display_name"], payload["role"]
                )
                return Response(201, result)
            if method == "POST" and path == "/sources":
                result = self.service.register_source(
                    actor(), payload["source_id"], payload["domain"], payload["label"]
                )
                return Response(201, result)
            if method == "POST" and path == "/calibrations":
                result = self.service.publish_calibration(
                    actor(), payload.get("basis", ""), payload.get("entries", [])
                )
                return Response(201, result)
            if method == "POST" and path == "/combos":
                result = self.service.register_combo(
                    actor(), payload["combo_id"], payload["domain"], payload["components"]
                )
                return Response(201, result)
            if method == "POST" and path == "/devices":
                result = self.service.register_device(
                    actor(), payload["device_id"], payload["domain"], payload.get("combo_id")
                )
                return Response(201, result)
            if method == "POST" and path == "/tickets":
                result = self.service.register_ticket(
                    actor(), payload["ticket_id"], payload["summary"], payload["domains"],
                    payload.get("combo_ids", []), payload["device_ids"],
                )
                return Response(201, result)
            if method == "POST" and path == "/safety-rules":
                return Response(201, self.service.register_safety_rule(actor(), payload))
            if method == "POST" and path == "/incidents":
                result = self.service.create_incident(actor(), payload["incident_id"], payload["title"])
                return Response(201, result)
            if method == "GET" and len(parts) == 2 and parts[0] == "incidents":
                return Response(200, self.service.get_incident(parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "events":
                key = normalized_headers.get("idempotency-key", "").strip()
                if not key:
                    raise ValidationFailed("缺少 Idempotency-Key")
                result = self.service.ingest_events(
                    actor(), parts[1], key, payload.get("events", [])
                )
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "late-evidence":
                result = self.service.submit_late_evidence(
                    actor(), parts[1], payload["reason"], payload.get("events", [])
                )
                return Response(201, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "reopen-requests" and parts[2] == "review":
                result = self.service.review_reopen(
                    actor(), int(parts[1]), bool(payload["approve"]), payload.get("note", "")
                )
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "revisions":
                result = self.service.build_revision(
                    actor(), parts[1], int(payload["calibration_version"])
                )
                return Response(201, result)
            if method == "GET" and len(parts) == 4 and parts[0] == "incidents" and parts[2] == "revisions":
                return Response(200, self.service.get_revision(parts[1], int(parts[3])))
            if method == "POST" and len(parts) == 5 and parts[0] == "incidents" and parts[2] == "revisions" and parts[4] == "replay":
                return Response(200, self.service.replay_revision(parts[1], int(parts[3])))
            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "freeze":
                result = self.service.freeze_conclusion(
                    actor(), parts[1], int(payload["revision_no"]),
                    [int(value) for value in payload["trigger_record_ids"]],
                    payload["decision_basis"], payload["rationale"],
                    bool(payload.get("conflict_acknowledged", False)),
                )
                return Response(201, result)
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "conclusion":
                return Response(200, self.service.get_conclusion(parts[1]))
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "plan":
                revision_values = query.get("revision_no")
                revision_no = None if not revision_values else int(revision_values[0])
                return Response(200, self.service.get_plan(parts[1], revision_no))
            if method == "POST" and len(parts) == 4 and parts[0] == "incidents" and parts[2] == "plan" and parts[3] == "confirm":
                return Response(200, self.service.confirm_plan(actor(), parts[1]))
            if (
                method == "POST" and len(parts) == 6 and parts[0] == "incidents"
                and parts[2] == "plan" and parts[3] == "devices" and parts[5] == "execute"
            ):
                result = self.service.execute_device_action(
                    actor(), parts[1], parts[4], payload["action"], payload.get("note", "")
                )
                return Response(200, result)
            if (
                method == "POST" and len(parts) == 6 and parts[0] == "incidents"
                and parts[2] == "plan" and parts[3] == "devices" and parts[5] == "fail"
            ):
                result = self.service.fail_device_action(
                    actor(), parts[1], parts[4], payload["action"], payload["error"]
                )
                return Response(200, result)
            if (
                method == "POST" and len(parts) == 6 and parts[0] == "incidents"
                and parts[2] == "plan" and parts[3] == "notifications" and parts[5] == "dispatched"
            ):
                return Response(200, self.service.mark_notified(actor(), parts[1], parts[4]))
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "report":
                return Response(200, self.service.report(actor(), parts[1]))
            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except ServiceError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    # 所有工作线程共享一个 SQLite 连接；串行化分发以保证事务不会跨请求交错。
    dispatch_lock = threading.RLock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "IncidentReplay/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            with dispatch_lock:
                response = application.handle(self.command, self.path, dict(self.headers.items()), body)
                encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动现场异常回放与安全回退 HTTP 服务")
    parser.add_argument("--database", type=Path, default=Path("incident_replay.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    application = JsonApplication(ReplayService(connection))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(application))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
