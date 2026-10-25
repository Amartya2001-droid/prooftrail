"""Week-1 HTTP API for ProofTrail (pure standard library).

Endpoints (all JSON; project routes need ``Authorization: Bearer <token>``):

- POST /api/users                     {username, name, password}
- POST /api/sessions                  {username, password} -> {token}
- POST /api/projects                  {title} -> {project_id}
- POST /api/projects/<id>/collaborators {username}
- POST /api/projects/<id>/uploads     {content_base64, label?, timestamp?}
- POST /api/projects/<id>/approvals   {content_id, timestamp?}
- GET  /api/projects/<id>/versions
- GET  /api/projects/<id>/versions/content?content_id=sha256:...
- GET  /api/projects/<id>/verify      (verification page: hashes, no text)

Run: python3 -m prooftrail.server --port 8000 --data prooftrail-data.json
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .auth import SessionStore, authenticate, create_user
from .persistence import load_state, save_state
from .store import Actor
from .verification import verification_page


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ProofTrailApp:
    """Business logic, independent of HTTP plumbing."""

    def __init__(self, data_path: str | None = None) -> None:
        self.data_path = data_path
        self.users, self.projects = load_state(data_path) if data_path else ({}, {})
        self.sessions = SessionStore()
        self._secrets: dict[str, bytes] = {}

    def _save(self) -> None:
        if self.data_path:
            save_state(self.data_path, self.users, self.projects)

    def _actor_for_token(self, token: str | None) -> Actor:
        actor_id = self.sessions.lookup(token)
        if actor_id is None or token not in self._secrets:
            raise ApiError(401, "unauthorized")
        user = self.users[actor_id]
        return Actor(actor_id, user.name, self._secrets[token], user.public_key)

    def _project_for(self, actor: Actor, project_id: str):
        project = self.projects.get(project_id)
        if project is None:
            raise ApiError(404, "project not found")
        if actor.actor_id not in project.collaborators:
            raise ApiError(403, "not a collaborator on this project")
        return project

    # -- users ---------------------------------------------------------------
    def register(self, username: str, name: str, password: str) -> dict:
        if username in self.users:
            raise ApiError(409, "username already exists")
        self.users[username] = create_user(username, name, password)
        self._save()
        return {"actor_id": username}

    def login(self, username: str, password: str) -> dict:
        user = self.users.get(username)
        if user is None:
            raise ApiError(401, "invalid credentials")
        secret = authenticate(user, password)
        if secret is None:
            raise ApiError(401, "invalid credentials")
        token = self.sessions.create(username)
        self._secrets[token] = secret
        return {"token": token, "actor_id": username}

    # -- projects ------------------------------------------------------------
    def create_project(self, token: str | None, title: str) -> dict:
        actor = self._actor_for_token(token)
        project_id = "proj-" + secrets.token_hex(6)
        from .store import Project

        project = Project(project_id, title)
        project.add_collaborator(actor)
        self.projects[project_id] = project
        self._save()
        return {"project_id": project_id}

    def add_collaborator(self, token: str | None, project_id: str,
                         username: str) -> dict:
        actor = self._actor_for_token(token)
        project = self._project_for(actor, project_id)
        user = self.users.get(username)
        if user is None:
            raise ApiError(404, "user not found")
        project.add_collaborator(
            Actor(username, user.name, b"", user.public_key))
        self._save()
        return {"project_id": project_id, "collaborator": username}

    def upload(self, token: str | None, project_id: str, content_b64: str,
               label: str = "", timestamp: str | None = None) -> dict:
        actor = self._actor_for_token(token)
        project = self._project_for(actor, project_id)
        try:
            data = base64.b64decode(content_b64, validate=True)
        except binascii.Error:
            raise ApiError(400, "content_base64 is not valid base64")
        version = project.upload(actor, data, timestamp or _now(), label)
        self._save()
        return {
            "content_id": version.content_id,
            "parent_content_id": version.parent_content_id,
            "label": version.label,
            "timestamp": version.timestamp,
        }

    def approve(self, token: str | None, project_id: str, content_id: str,
                timestamp: str | None = None) -> dict:
        actor = self._actor_for_token(token)
        project = self._project_for(actor, project_id)
        version = next((v for v in project.versions
                        if v.content_id == content_id), None)
        if version is None:
            raise ApiError(404, "version not found")
        project.approve(actor, version, timestamp or _now())
        self._save()
        return {"approved": content_id}

    def versions(self, token: str | None, project_id: str) -> dict:
        actor = self._actor_for_token(token)
        project = self._project_for(actor, project_id)
        return {"versions": [
            {"content_id": v.content_id, "parent_content_id": v.parent_content_id,
             "actor_id": v.actor_id, "timestamp": v.timestamp, "label": v.label}
            for v in project.versions
        ]}

    def version_content(self, token: str | None, project_id: str,
                        content_id: str) -> dict:
        actor = self._actor_for_token(token)
        project = self._project_for(actor, project_id)
        version = next((v for v in project.versions
                        if v.content_id == content_id), None)
        if version is None:
            raise ApiError(404, "version not found")
        return {"content_base64": base64.b64encode(
            project.read(version)).decode()}

    def verify(self, token: str | None, project_id: str) -> dict:
        actor = self._actor_for_token(token)
        project = self._project_for(actor, project_id)
        texts = [project.read(v).decode(errors="replace")
                 for v in project.versions]
        return verification_page(project, texts)


def make_handler(app: ProofTrailApp):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep test output clean
            pass

        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                raise ApiError(400, "body is not valid JSON")

        def _token(self) -> str | None:
            auth = self.headers.get("Authorization") or ""
            if auth.startswith("Bearer "):
                return auth[7:]
            return None

        def _route(self, method: str, path: str, query: dict, body: dict):
            parts = [p for p in path.split("/") if p]
            token = self._token()
            if method == "POST" and parts == ["api", "users"]:
                return 201, app.register(body["username"], body["name"],
                                         body["password"])
            if method == "POST" and parts == ["api", "sessions"]:
                return 200, app.login(body["username"], body["password"])
            if method == "POST" and parts == ["api", "projects"]:
                return 201, app.create_project(token, body["title"])
            if (method == "POST" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "collaborators"):
                return 200, app.add_collaborator(token, parts[2],
                                                 body["username"])
            if (method == "POST" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "uploads"):
                return 201, app.upload(token, parts[2], body["content_base64"],
                                       body.get("label", ""),
                                       body.get("timestamp"))
            if (method == "POST" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "approvals"):
                return 200, app.approve(token, parts[2], body["content_id"],
                                        body.get("timestamp"))
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "versions"):
                return 200, app.versions(token, parts[2])
            if (method == "GET" and len(parts) == 5
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "versions" and parts[4] == "content"):
                return 200, app.version_content(
                    token, parts[2], query.get("content_id", [""])[0])
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "verify"):
                return 200, app.verify(token, parts[2])
            raise ApiError(404, "route not found")

        def _handle(self, method: str) -> None:
            try:
                parsed = urlparse(self.path)
                body = self._read_json() if method == "POST" else {}
                status, payload = self._route(
                    method, parsed.path, parse_qs(parsed.query), body)
                self._send(status, payload)
            except ApiError as exc:
                self._send(exc.status, {"error": exc.message})
            except KeyError as exc:
                self._send(400, {"error": f"missing field: {exc.args[0]}"})
            except Exception as exc:  # never leak a stack trace as HTML
                self._send(500, {"error": str(exc)})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return Handler


def make_server(host: str, port: int, data_path: str | None = None):
    app = ProofTrailApp(data_path)
    return ThreadingHTTPServer((host, port), make_handler(app)), app


def main() -> None:
    parser = argparse.ArgumentParser(description="ProofTrail week-1 API server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data", default="prooftrail-data.json")
    args = parser.parse_args()
    server, _ = make_server(args.host, args.port, args.data)
    print(f"ProofTrail API on http://{args.host}:{args.port} "
          f"(data: {args.data})")
    server.serve_forever()


if __name__ == "__main__":
    main()
