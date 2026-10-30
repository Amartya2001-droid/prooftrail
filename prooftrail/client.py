"""Thin Python client for the ProofTrail HTTP API (stdlib only).

Example:
    client = ProofTrailClient("http://127.0.0.1:8000")
    client.register("alice", "Alice", "password123")
    client.login("alice", "password123")
    project = client.create_project("Brand brief")
    client.upload(project["project_id"], b"first draft", label="v1")
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request


class ProofTrailError(Exception):
    """An API error: carries the HTTP status and the server's message."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class ProofTrailClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token: str | None = None

    def _request(self, method: str, path: str, body: dict | None = None,
                 token: str | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        auth = token if token is not None else self.token
        if auth:
            headers["Authorization"] = f"Bearer {auth}"
        request = urllib.request.Request(
            self.base_url + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read() or b"{}").get(
                    "error", exc.reason)
            except json.JSONDecodeError:
                message = exc.reason
            raise ProofTrailError(exc.code, message) from exc

    def health(self) -> dict:
        return self._request("GET", "/api/health")

    def register(self, username: str, name: str, password: str) -> dict:
        return self._request("POST", "/api/users",
                             {"username": username, "name": name,
                              "password": password})

    def login(self, username: str, password: str,
              totp_code: str | None = None,
              recovery_code: str | None = None) -> str:
        """Log in. Returns the session token, or, when TOTP is
        enabled and no second factor was supplied, the pending
        token to complete with :meth:`totp_verify`."""
        body: dict = {"username": username, "password": password}
        if totp_code is not None:
            body["totp_code"] = totp_code
        if recovery_code is not None:
            body["recovery_code"] = recovery_code
        result = self._request("POST", "/api/sessions", body)
        if "token" in result:
            self.token = result["token"]
            return self.token
        self.token = None
        return result["pending_token"]

    def totp_verify(self, pending_token: str, code: str | None = None,
                    recovery_code: str | None = None) -> str:
        body: dict = {"pending_token": pending_token}
        if code is not None:
            body["code"] = code
        if recovery_code is not None:
            body["recovery_code"] = recovery_code
        result = self._request("POST", "/api/sessions/totp", body)
        self.token = result["token"]
        return self.token

    def change_password(self, old_password: str,
                        new_password: str) -> dict:
        return self._request("POST", "/api/users/password",
                             {"old_password": old_password,
                              "new_password": new_password})

    def totp_setup(self) -> dict:
        return self._request("POST", "/api/users/totp/setup", {})

    def totp_confirm(self, code: str) -> dict:
        return self._request("POST", "/api/users/totp/confirm",
                             {"code": code})

    def totp_disable(self, password: str) -> dict:
        return self._request("POST", "/api/users/totp/disable",
                             {"password": password})

    def sessions(self) -> dict:
        return self._request("GET", "/api/sessions")

    def revoke_session(self, session_id: str) -> dict:
        return self._request("POST", "/api/sessions/revoke-one",
                             {"session_id": session_id})

    def audit(self) -> dict:
        return self._request("GET", "/api/sessions/audit")

    def openapi(self) -> dict:
        return self._request("GET", "/api/openapi.json")

    def logout(self) -> dict:
        body = self._request("POST", "/api/sessions/revoke")
        self.token = None
        return body

    def logout_all(self) -> dict:
        body = self._request("POST", "/api/sessions/revoke-all")
        self.token = None
        return body

    def create_project(self, title: str) -> dict:
        return self._request("POST", "/api/projects", {"title": title})

    def list_projects(self, limit: int = 50, offset: int = 0) -> dict:
        return self._request(
            "GET", f"/api/projects?limit={limit}&offset={offset}")

    def add_collaborator(self, project_id: str, username: str) -> dict:
        return self._request(
            "POST", f"/api/projects/{project_id}/collaborators",
            {"username": username})

    def remove_collaborator(self, project_id: str, username: str) -> dict:
        return self._request(
            "POST", f"/api/projects/{project_id}/collaborators/remove",
            {"username": username})

    def upload(self, project_id: str, data: bytes, label: str = "",
               filename: str = "",
               content_type: str = "application/octet-stream") -> dict:
        return self._request(
            "POST", f"/api/projects/{project_id}/uploads",
            {"content_base64": base64.b64encode(data).decode(),
             "label": label, "filename": filename,
             "content_type": content_type})

    def approve(self, project_id: str, content_id: str) -> dict:
        return self._request("POST", f"/api/projects/{project_id}/approvals",
                             {"content_id": content_id})

    def declare(self, project_id: str, content_id: str, tool: str,
                prompt_summary: str = "",
                sentence_indices: list | None = None) -> dict:
        return self._request(
            "POST", f"/api/projects/{project_id}/declarations",
            {"content_id": content_id, "tool": tool,
             "prompt_summary": prompt_summary,
             "sentence_indices": sentence_indices or []})

    def declarations(self, project_id: str) -> dict:
        return self._request("GET", f"/api/projects/{project_id}/declarations")

    def contributions(self, project_id: str) -> dict:
        return self._request(
            "GET", f"/api/projects/{project_id}/contributions")

    def diff(self, project_id: str, from_id: str | None = None,
             to_id: str | None = None) -> dict:
        from urllib.parse import urlencode
        params = {k: v for k, v in
                  (("from", from_id), ("to", to_id)) if v is not None}
        query = f"?{urlencode(params)}" if params else ""
        return self._request("GET", f"/api/projects/{project_id}/diff{query}")

    def versions(self, project_id: str, limit: int = 50,
                 offset: int = 0) -> dict:
        return self._request(
            "GET",
            f"/api/projects/{project_id}/versions"
            f"?limit={limit}&offset={offset}")

    def version_content(self, project_id: str, content_id: str) -> bytes:
        body = self._request(
            "GET",
            f"/api/projects/{project_id}/versions/content"
            f"?content_id={content_id}")
        return base64.b64decode(body["content_base64"])

    def events(self, project_id: str, limit: int = 50,
               offset: int = 0) -> dict:
        return self._request(
            "GET",
            f"/api/projects/{project_id}/events"
            f"?limit={limit}&offset={offset}")

    def verify(self, project_id: str) -> dict:
        return self._request("GET", f"/api/projects/{project_id}/verify")

    def export(self, project_id: str, claim: str = "") -> dict:
        from urllib.parse import quote
        return self._request(
            "GET",
            f"/api/projects/{project_id}/export?claim={quote(claim)}")

    def verify_bundle(self, bundle: dict) -> dict:
        return self._request("POST", "/api/bundles/verify", bundle)
