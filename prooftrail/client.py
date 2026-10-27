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

    def login(self, username: str, password: str) -> str:
        body = self._request("POST", "/api/sessions",
                             {"username": username, "password": password})
        self.token = body["token"]
        return self.token

    def logout(self) -> dict:
        body = self._request("POST", "/api/sessions/revoke")
        self.token = None
        return body

    def create_project(self, title: str) -> dict:
        return self._request("POST", "/api/projects", {"title": title})

    def list_projects(self) -> dict:
        return self._request("GET", "/api/projects")

    def add_collaborator(self, project_id: str, username: str) -> dict:
        return self._request(
            "POST", f"/api/projects/{project_id}/collaborators",
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

    def versions(self, project_id: str) -> dict:
        return self._request("GET", f"/api/projects/{project_id}/versions")

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
