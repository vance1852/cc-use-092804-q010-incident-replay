"""无第三方依赖的 HTTP JSON 接口。

所有写接口要求 ``X-Actor-`` 请求头标识操作者；事件导入还要求
``Idempotency-Key``，重复提交返回同一结果而不产生重复到达记录。
"""

from __future__ import annotations

import argparse
import json
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
        h = {key.lower(): value for key, value in (headers or {}).items()}
        path = urlparse(target).path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        actor = lambda: self._actor(h)  # noqa: E731
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}

            if method == "POST" and path == "/users":
                result = self.service.create_user(
                    payload["user_id"], payload["display_name"], payload["role"]
                )
                return Response(201, result)

            if method == "POST" and path == "/incidents":
                result = self.service.create_incident(
                    actor(), payload["incident_id"], payload["title"],
                    payload.get("drift_threshold_ms"),
                )
                return Response(201, result)
            if method == "GET" and len(parts) == 2 and parts[0] == "incidents":
                return Response(200, self.service.get_incident(parts[1]))
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "report":
                return Response(200, self.service.report(actor(), parts[1]))
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "timeline":
                actor()
                return Response(200, self.service.current_timeline(parts[1]))

            if method == "POST" and path == "/devices":
                result = self.service.register_device(
                    actor(), payload["incident_id"], payload["device_id"], payload["kind"],
                    payload["owner_team"], payload.get("contacts", []),
                )
                return Response(201, result)
            if method == "POST" and path == "/deployments":
                result = self.service.upsert_deployment(
                    actor(), payload["incident_id"], payload["device_id"], payload["component"],
                    payload["version"], payload["digest"],
                )
                return Response(200, result)
            if method == "POST" and path == "/tickets":
                result = self.service.register_ticket(
                    actor(), payload["incident_id"], payload["ticket_id"], payload["domain"],
                    payload["title"], payload.get("device_ids", []), payload.get("components", []),
                )
                return Response(201, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "tickets" and parts[2] == "status":
                # /tickets/{ticket_id}/status 携带 incident_id
                result = self.service.update_ticket_status(
                    actor(), payload["incident_id"], parts[1], payload["status"]
                )
                return Response(200, result)
            if method == "POST" and path == "/safety-rules":
                return Response(201, self.service.register_safety_rule(actor(), payload["incident_id"], payload))

            if method == "POST" and path == "/calibrations":
                return Response(201, self.service.add_calibration(actor(), payload["incident_id"], payload))

            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "events":
                key = h.get("idempotency-key", "").strip()
                if not key:
                    raise ValidationFailed("缺少 Idempotency-Key")
                result = self.service.ingest_events(
                    actor(), parts[1], key, payload.get("events", [])
                )
                return Response(200, result)

            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "freeze":
                result = self.service.freeze_revision(
                    actor(), parts[1], int(payload["expected_revision"]), payload["rationale"]
                )
                return Response(201, result)
            if method == "GET" and len(parts) == 4 and parts[0] == "incidents" and parts[2] == "revisions":
                return Response(200, self.service.get_revision(parts[1], int(parts[3])))
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "revisions":
                return Response(200, {"revisions": self.service.list_revisions(parts[1])})

            if method == "POST" and path == "/reopens":
                result = self.service.request_reopen(actor(), payload["incident_id"], payload["reason"])
                return Response(201, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "reopens" and parts[2] == "review":
                result = self.service.review_reopen(
                    actor(), int(parts[1]), bool(payload["approve"]), payload.get("note", "")
                )
                return Response(200, result)

            if method == "POST" and path == "/rollback-plans":
                result = self.service.propose_plan(
                    actor(), payload["incident_id"], int(payload["revision"]), payload["rationale"]
                )
                return Response(201, result)
            if method == "GET" and len(parts) == 2 and parts[0] == "rollback-plans":
                return Response(200, self.service.get_plan(int(parts[1])))
            if method == "POST" and len(parts) == 3 and parts[0] == "rollback-plans" and parts[2] == "review":
                result = self.service.review_plan(
                    actor(), int(parts[1]), bool(payload["approve"]), payload.get("note", "")
                )
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "rollback-plans" and parts[2] == "cancel":
                result = self.service.cancel_plan(actor(), int(parts[1]), payload.get("note", ""))
                return Response(200, result)
            if method == "POST" and len(parts) == 3 and parts[0] == "rollback-plans" and parts[2] == "actions":
                result = self.service.update_action(
                    actor(), int(parts[1]), int(payload["action_id"]),
                    payload["status"], payload.get("note", ""),
                )
                return Response(200, result)
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "progress":
                revision = int(qs_value(target, "revision")) if qs_value(target, "revision") else None
                return Response(200, self.service.device_progress(parts[1], revision))

            if method == "POST" and path == "/notifications":
                result = self.service.dispatch_notification(
                    actor(), payload["incident_id"], int(payload["revision"]), payload["channel"]
                )
                return Response(201, result)
            if method == "GET" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "notifications":
                return Response(200, {"notifications": self.service.list_notifications(parts[1])})

            if method == "POST" and len(parts) == 3 and parts[0] == "incidents" and parts[2] == "close":
                return Response(200, self.service.close_incident(actor(), parts[1]))

            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except ServiceError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def qs_value(target: str, key: str) -> str | None:
    values = parse_qs(urlparse(target).query).get(key)
    return None if not values else values[0]


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "IncidentReplay/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
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
    parser = argparse.ArgumentParser(description="启动现场异常确定性回放与安全回退 HTTP 服务")
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
