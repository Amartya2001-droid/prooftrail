"""Week-1 HTTP API for ProofTrail (pure standard library).

Endpoints (all JSON; project routes need ``Authorization: Bearer <token>``):

- POST /api/users                     {username, name, password}
- POST /api/sessions                  {username, password} -> {token}
- POST /api/sessions/revoke           (Bearer token; logs out)
- POST /api/sessions/revoke-all       (Bearer token; logs out everywhere)
- GET  /api/sessions/audit            (Bearer token; own auth events)
- GET  /api/sessions                 (Bearer token; own sessions)
- POST /api/sessions/revoke-one       (Bearer token; revoke one session)
- POST /api/projects                  {title} -> {project_id}
- POST /api/projects/<id>/collaborators {username}
- POST /api/projects/<id>/uploads     {content_base64, label?, timestamp?}
- POST /api/projects/<id>/approvals   {content_id, timestamp?}
- POST /api/projects/<id>/declarations {content_id, tool, prompt_summary?, sentence_indices?}
- GET  /api/projects/<id>/declarations
- GET  /api/projects/<id>/contributions (Human Contribution Map)
- GET  /api/projects/<id>/diff?from=...&to=... (semantic sentence diff)
- GET  /api/projects/<id>/versions
- GET  /api/projects/<id>/versions/content?content_id=sha256:...
- GET  /api/projects/<id>/verify      (verification page: hashes, no text)
- POST /api/bundles/verify            (verify a signed bundle; no auth)

Run: python3 -m prooftrail.server --port 8000 --data prooftrail-data.json
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import json
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .auth import (
    AuditLog,
    SessionStore,
    authenticate,
    authenticate_unknown,
    create_user,
    validate_password,
)
from .contributions import build_map
from .crypto import content_id
from .diffing import diff_texts
from .persistence import load_state, save_state
from .store import Actor
from .verification import (
    build_evidence_bundle,
    verification_page,
    verify_evidence_bundle,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "ProofTrail API", "version": __version__},
    "paths": {
        "/api/health": {"get": {"summary": "Liveness check, no auth"}},
        "/api/users": {"post": {"summary": "Register a user"}},
        "/api/sessions": {"post": {"summary": "Log in, returns a token"}},
        "/api/sessions/revoke": {
            "post": {"summary": "Log out, requires Bearer token"}},
        "/api/sessions/revoke-all": {
            "post": {"summary": "Log out everywhere, requires Bearer token"}},
        "/api/sessions/audit": {
            "get": {"summary": "My authentication audit trail, requires Bearer token"}},
        "/api/sessions": {
            "get": {"summary": "My sessions, requires Bearer token"}},
        "/api/sessions/revoke-one": {
            "post": {"summary": "Revoke one session by id, requires Bearer token"}},
        "/api/projects": {
            "post": {"summary": "Create a project, requires Bearer token"},
            "get": {"summary": "List my projects, requires Bearer token"}},
        "/api/projects/{id}/collaborators": {
            "post": {"summary": "Add a collaborator"}},
        "/api/projects/{id}/uploads": {
            "post": {"summary": "Upload a version (idempotent on identical bytes)"}},
        "/api/projects/{id}/approvals": {
            "post": {"summary": "Approve a version"}},
        "/api/projects/{id}/declarations": {
            "post": {"summary": "Declare AI use for a version"},
            "get": {"summary": "List AI-use declarations"}},
        "/api/projects/{id}/contributions": {
            "get": {"summary": "Human Contribution Map: per-sentence sources"}},
        "/api/projects/{id}/diff": {
            "get": {"summary": "Semantic diff between two versions"}},
        "/api/projects/{id}/versions": {
            "get": {"summary": "List versions with metadata"}},
        "/api/projects/{id}/versions/content": {
            "get": {"summary": "Download one version's bytes"}},
        "/api/projects/{id}/events": {
            "get": {"summary": "Ledger events, newest first, paged"}},
        "/api/projects/{id}/verify": {
            "get": {"summary": "Verification page: hashes, no text"}},
        "/api/projects/{id}/export": {
            "get": {"summary": "Signed dispute evidence bundle"}},
        "/api/bundles/verify": {
            "post": {"summary": "Verify a signed bundle, no auth required"}},
    },
}


def _health() -> dict:
    return {"status": "ok", "version": __version__}


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _validate_username(username: str) -> None:
    if not _USERNAME_RE.match(username or ""):
        raise ApiError(
            400,
            "username must be 3-32 characters: letters, digits, _, - or .")


def _validate_text(field: str, value: str, max_len: int,
                   required: bool = False) -> None:
    if value is None:
        value = ""
    if required and not value.strip():
        raise ApiError(400, f"{field} must not be empty")
    if len(value) > max_len:
        raise ApiError(400, f"{field} must be at most {max_len} characters")


def _validate_filename(filename: str) -> None:
    if len(filename) > 255:
        raise ApiError(400, "filename must be at most 255 characters")
    if "/" in filename or "\\" in filename or filename in (".", ".."):
        raise ApiError(400, "filename must be a plain file name")


def _parse_paging(query: dict) -> tuple[int, int]:
    """Shared limit/offset parsing: limit 1-200, offset >= 0."""
    try:
        limit = int(query.get("limit", ["50"])[0])
        offset = int(query.get("offset", ["0"])[0])
    except ValueError:
        raise ApiError(400, "limit and offset must be integers") from None
    if not 1 <= limit <= 200:
        raise ApiError(400, "limit must be between 1 and 200")
    if offset < 0:
        raise ApiError(400, "offset must not be negative")
    return limit, offset


# Maximum request body: 10 MiB. Anything larger is rejected before it is
# read, so a huge upload cannot exhaust server memory.
MAX_BODY_BYTES = 10 * 1024 * 1024
# Login brute-force defence: 5 failures in 10 minutes locks the username
# for 15 minutes (correct password included — that is the point).
LOGIN_FAIL_WINDOW_SECONDS = 600
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 900
# Registration abuse defence: an open deployment must not accumulate
# junk accounts from one address. 30 per hour per client IP is far above
# any legitimate signup burst and far below bot volume.
REGISTER_WINDOW_SECONDS = 3600
REGISTER_MAX_PER_IP = 30
# Login spray defence: the per-username lockout stops guessing one
# account, but not spraying many accounts from one address. 20 failed
# logins in 10 minutes from one address locks that address out.
LOGIN_IP_WINDOW_SECONDS = 600
LOGIN_IP_MAX_FAILURES = 20
# General API throttle: no single address should be able to flood
# the API. 300 requests per minute per address is far above any
# legitimate client burst and far below abuse volume.
REQUEST_WINDOW_SECONDS = 60
REQUEST_MAX_PER_IP = 300


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
        # One lock serialises all mutations (and the saves that follow
        # them) so concurrent threads cannot interleave a register,
        # upload or save into a corrupt state.
        self._lock = threading.RLock()
        self._failed_logins: dict[str, list[float]] = {}
        self._lockouts: dict[str, float] = {}
        self._registrations: dict[str, list[float]] = {}
        self._failed_logins_ip: dict[str, list[float]] = {}
        self._request_counts: dict[str, list[float]] = {}
        self.audit = AuditLog()
        # Addresses each account has logged in from before, for the
        # new-address flag. In memory like sessions and the audit log:
        # a restart forgets familiarity, and the next login from any
        # address is flagged once — fail-visible, not fail-open.
        self._known_ips: dict[str, set[str]] = {}
        # Per-request client identity, set by the HTTP layer for the
        # thread handling that request (threading.local, so concurrent
        # requests cannot see each other's). In-process callers have
        # no context, and their sessions are unbound.
        self._request_local = threading.local()

    @contextlib.contextmanager
    def request_context(self, remote_addr: str | None,
                        user_agent: str | None):
        """Scope one request's client identity for session binding."""
        self._request_local.remote_addr = remote_addr
        self._request_local.user_agent = user_agent
        try:
            yield
        finally:
            self._request_local.remote_addr = None
            self._request_local.user_agent = None

    def check_request_rate(self, remote_addr: str | None) -> None:
        """General per-address throttle, enforced by the HTTP layer
        on every request. In-process app callers pass no address and
        are not throttled."""
        if remote_addr is None:
            return
        now = time.time()
        counts = [t for t in self._request_counts.get(remote_addr, [])
                  if now - t < REQUEST_WINDOW_SECONDS]
        counts.append(now)
        self._request_counts[remote_addr] = counts
        if len(counts) > REQUEST_MAX_PER_IP:
            raise ApiError(429, "too many requests from this address")

    def _save(self) -> None:
        if self.data_path:
            save_state(self.data_path, self.users, self.projects)

    def _actor_for_token(self, token: str | None) -> Actor:
        remote_addr = getattr(self._request_local, "remote_addr", None)
        user_agent = getattr(self._request_local, "user_agent", None)
        actor_id = self.sessions.lookup(token, remote_addr, user_agent)
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
    def register(self, username: str, name: str, password: str,
                 remote_addr: str | None = None) -> dict:
        with self._lock:
            # Usernames are case-insensitive: without this, "Designer"
            # and "designer" would be two accounts, and a lookalike
            # name could sign ledger events that look like someone
            # else's. The display name keeps its original case.
            username = username.lower()
            if remote_addr is not None:
                now = time.time()
                attempts = [t for t in self._registrations.get(remote_addr, [])
                            if now - t < REGISTER_WINDOW_SECONDS]
                if len(attempts) >= REGISTER_MAX_PER_IP:
                    raise ApiError(
                        429, "too many registrations from this address")
                attempts.append(now)
                self._registrations[remote_addr] = attempts
            _validate_username(username)
            _validate_text("name", name, 100, required=True)
            if username in self.users:
                self.audit.record("register_failed", username, remote_addr,
                                  "username already exists")
                raise ApiError(409, "username already exists")
            try:
                validate_password(username, password)
            except ValueError as exc:
                raise ApiError(400, str(exc)) from exc
            self.users[username] = create_user(username, name, password)
            self.audit.record("register", username, remote_addr)
            self._save()
            return {"actor_id": username}

    def _record_failed_login(self, username: str, now: float,
                             remote_addr: str | None = None) -> None:
        attempts = [t for t in self._failed_logins.get(username, [])
                    if now - t < LOGIN_FAIL_WINDOW_SECONDS]
        attempts.append(now)
        self._failed_logins[username] = attempts
        if len(attempts) >= LOGIN_MAX_FAILURES:
            self._lockouts[username] = now + LOGIN_LOCKOUT_SECONDS
            self.audit.record("lockout", username, remote_addr,
                              "5 failed logins in 10 minutes")

    def _record_failed_login_ip(self, remote_addr: str, now: float) -> None:
        attempts = [t for t in self._failed_logins_ip.get(remote_addr, [])
                    if now - t < LOGIN_IP_WINDOW_SECONDS]
        attempts.append(now)
        self._failed_logins_ip[remote_addr] = attempts

    def login(self, username: str, password: str,
              remote_addr: str | None = None,
              user_agent: str | None = None) -> dict:
        with self._lock:
            username = username.lower()
            now = time.time()
            if now < self._lockouts.get(username, 0):
                raise ApiError(429, "account locked after failed logins")
            if remote_addr is not None:
                ip_attempts = [
                    t for t in self._failed_logins_ip.get(remote_addr, [])
                    if now - t < LOGIN_IP_WINDOW_SECONDS]
                if len(ip_attempts) >= LOGIN_IP_MAX_FAILURES:
                    raise ApiError(
                        429, "too many failed logins from this address")
            user = self.users.get(username)
            # Same response for unknown users and wrong passwords, so a
            # login oracle cannot enumerate accounts — and the same
            # PBKDF2 work, so the timing cannot either.
            if user is None:
                authenticate_unknown(password)
                secret = None
            else:
                secret = authenticate(user, password)
            if secret is None:
                self._record_failed_login(username, now, remote_addr)
                self.audit.record("login_failed", username, remote_addr)
                if remote_addr is not None:
                    self._record_failed_login_ip(remote_addr, now)
                raise ApiError(401, "invalid credentials")
            self._failed_logins.pop(username, None)
            self._lockouts.pop(username, None)
            self.sessions.prune()
            # A successful login from an address this account has never
            # used before is flagged, so the account holder can tell a
            # legitimate new location from a stolen password at a
            # glance. Logins without an address (in-process callers)
            # cannot be judged and are not flagged.
            known = self._known_ips.setdefault(username, set())
            new_ip = remote_addr is not None and remote_addr not in known
            if remote_addr is not None:
                known.add(remote_addr)
            token = self.sessions.create(username, remote_addr, user_agent)
            self._secrets[token] = secret
            self.audit.record("login", username, remote_addr,
                              "new address" if new_ip else "")
            return {"token": token, "actor_id": username, "new_ip": new_ip}

    def logout(self, token: str | None) -> dict:
        with self._lock:
            if token:
                actor_id = self.sessions.lookup(token)
                self.sessions.revoke(token)
                self._secrets.pop(token, None)
                self.audit.record("logout", actor_id)
            return {"revoked": True}

    def logout_all(self, token: str | None) -> dict:
        """Log the caller out everywhere: revoke every session for
        their account, including the calling token, and drop the
        associated signing secrets. For a lost or shared device,
        revoking one token leaves the others live, so this is the
        control that actually ends access."""
        with self._lock:
            actor = self._actor_for_token(token)
            revoked = self.sessions.revoke_all(actor.actor_id)
            for revoked_token in revoked:
                self._secrets.pop(revoked_token, None)
            self.audit.record("revoke_all", actor.actor_id, None,
                              f"{len(revoked)} sessions")
            return {"revoked": len(revoked)}

    def audit_for(self, token: str | None) -> dict:
        """The caller's own authentication events, newest first."""
        with self._lock:
            actor = self._actor_for_token(token)
            return {"events": self.audit.events_for(actor.actor_id)}

    def sessions_for(self, token: str | None) -> dict:
        """The caller's own sessions, with the calling one flagged.
        Tokens never appear: session_id is the revocation handle."""
        with self._lock:
            actor = self._actor_for_token(token)
            current = self.sessions.record_for_token(token)
            current_id = current.session_id if current else None
            sessions = self.sessions.list_sessions(actor.actor_id)
            for session in sessions:
                session["current"] = session["session_id"] == current_id
            return {"sessions": sessions}

    def revoke_session(self, token: str | None,
                       session_id: str) -> dict:
        """Revoke one of the caller's sessions by id. A foreign or
        unknown id is a plain 404: confirming which ids exist would
        leak other users' sessions."""
        with self._lock:
            actor = self._actor_for_token(token)
            revoked = self.sessions.revoke_session(actor.actor_id,
                                                   session_id)
            if revoked is None:
                raise ApiError(404, "session not found")
            self._secrets.pop(revoked, None)
            self.audit.record("session_revoked", actor.actor_id, None,
                              session_id)
            return {"revoked": True}

    # -- projects ------------------------------------------------------------
    def create_project(self, token: str | None, title: str) -> dict:
        with self._lock:
            _validate_text("title", title, 200, required=True)
            actor = self._actor_for_token(token)
            # 128-bit random id: unguessable, and the collaborator check
            # below is the real authorisation in any case.
            project_id = "proj-" + secrets.token_hex(16)
            from .store import Project

            project = Project(project_id, title)
            project.add_collaborator(actor)
            project.creator_id = actor.actor_id
            self.projects[project_id] = project
            self._save()
            return {"project_id": project_id}

    def list_projects(self, token: str | None,
                      limit: int = 50, offset: int = 0) -> dict:
        """Projects the caller collaborates on, newest first, paged."""
        if not 1 <= limit <= 200:
            raise ApiError(400, "limit must be between 1 and 200")
        if offset < 0:
            raise ApiError(400, "offset must not be negative")
        with self._lock:
            actor = self._actor_for_token(token)
            mine = [p for p in self.projects.values()
                    if actor.actor_id in p.collaborators]
            mine.sort(key=lambda p: p.project_id, reverse=True)
            page = mine[offset:offset + limit]
            return {"projects": [
                {"project_id": p.project_id, "title": p.title,
                 "versions": len(p.versions),
                 "collaborators": sorted(p.collaborators)}
                for p in page
            ], "total": len(mine), "limit": limit, "offset": offset}

    def add_collaborator(self, token: str | None, project_id: str,
                         username: str) -> dict:
        with self._lock:
            username = username.lower()
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            # Inviting is a creator-only power. Without this, any
            # collaborator — including one added for a single review —
            # could invite anyone else into the project and its history.
            if (project.creator_id is not None
                    and actor.actor_id != project.creator_id):
                raise ApiError(
                    403, "only the project creator can add collaborators")
            user = self.users.get(username)
            if user is None:
                raise ApiError(404, "user not found")
            project.add_collaborator(
                Actor(username, user.name, b"", user.public_key))
            self._save()
            return {"project_id": project_id, "collaborator": username}

    def upload(self, token: str | None, project_id: str, content_b64: str,
               label: str = "", filename: str = "",
               content_type: str = "application/octet-stream") -> dict:
        with self._lock:
            _validate_text("label", label, 100)
            _validate_filename(filename)
            _validate_text("content_type", content_type, 100)
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            try:
                data = base64.b64decode(content_b64, validate=True)
            except binascii.Error:
                raise ApiError(400, "content_base64 is not valid base64")
            if not data:
                raise ApiError(
                    400, "content must not be empty: a zero-byte version "
                    "is not meaningful provenance")
            # Timestamps are always server-assigned. A provenance ledger
            # must never trust the uploader's clock.
            # Idempotency: identical bytes to the latest version are the
            # same version. Re-uploading them must not spam the ledger
            # with a duplicate event.
            latest = project.versions[-1] if project.versions else None
            if latest is not None and latest.content_id == content_id(data):
                return {
                    "content_id": latest.content_id,
                    "parent_content_id": latest.parent_content_id,
                    "label": latest.label,
                    "timestamp": latest.timestamp,
                    "filename": latest.filename,
                    "content_type": latest.content_type,
                    "size": latest.size,
                    "duplicate": True,
                }
            version = project.upload(actor, data, _now(), label,
                                     filename=filename,
                                     content_type=content_type)
            self._save()
            return {
                "content_id": version.content_id,
                "parent_content_id": version.parent_content_id,
                "label": version.label,
                "timestamp": version.timestamp,
                "filename": version.filename,
                "content_type": version.content_type,
                "size": version.size,
                "duplicate": False,
            }

    def approve(self, token: str | None, project_id: str,
                content_id: str) -> dict:
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            version = next((v for v in project.versions
                            if v.content_id == content_id), None)
            if version is None:
                raise ApiError(404, "version not found")
            project.approve(actor, version, _now())
            self._save()
            return {"approved": content_id}

    def declare(self, token: str | None, project_id: str, content_id: str,
                tool: str, prompt_summary: str = "",
                sentence_indices: list | None = None) -> dict:
        with self._lock:
            _validate_text("tool", tool, 100, required=True)
            _validate_text("prompt_summary", prompt_summary, 500)
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            version = next((v for v in project.versions
                            if v.content_id == content_id), None)
            if version is None:
                raise ApiError(404, "version not found")
            try:
                project.declare(actor, version, tool, prompt_summary,
                                sentence_indices or [], _now())
            except ValueError as exc:
                raise ApiError(400, str(exc)) from exc
            self._save()
            return {"declared": content_id, "tool": tool}

    def declarations(self, token: str | None, project_id: str) -> dict:
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            return {"declarations": [
                {"version_label": d.version_label, "actor_id": d.actor_id,
                 "tool": d.tool, "prompt_summary": d.prompt_summary,
                 "sentence_indices": d.sentence_indices}
                for d in project.declarations()
            ]}

    def contributions(self, token: str | None, project_id: str) -> dict:
        """Human Contribution Map: every sentence, its source, and the
        share of each source across the project."""
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            cmap = self._contribution_map(project)
            return {
                "segments": [
                    {"text": s.text, "source": s.source,
                     "first_seen_version": s.first_seen_version}
                    for s in cmap.segments
                ],
                "coverage_pct": cmap.coverage(),
                "caveat": cmap.caveat,
            }

    def _contribution_map(self, project):
        texts = [project.read(v).decode(errors="replace")
                 for v in project.versions]
        return build_map(
            [(v.label, t) for v, t in zip(project.versions, texts)],
            project.declarations())

    def diff(self, token: str | None, project_id: str,
             from_id: str | None = None,
             to_id: str | None = None) -> dict:
        """Semantic sentence diff between two versions.

        Defaults, when ids are omitted, are the latest version and its
        parent — the change a reader most often wants to see.
        """
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            by_id = {v.content_id: v for v in project.versions}
            if to_id is None:
                if not project.versions:
                    raise ApiError(404, "project has no versions")
                to_version = project.versions[-1]
            else:
                to_version = by_id.get(to_id)
                if to_version is None:
                    raise ApiError(404, "to version not found")
            if from_id is None:
                if to_version.parent_content_id is None:
                    raise ApiError(
                        400, "first version has nothing to diff against")
                from_version = by_id[to_version.parent_content_id]
            else:
                from_version = by_id.get(from_id)
                if from_version is None:
                    raise ApiError(404, "from version not found")
            old = project.read(from_version).decode(errors="replace")
            new = project.read(to_version).decode(errors="replace")
            result = diff_texts(old, new)
            return {
                "from_content_id": from_version.content_id,
                "from_label": from_version.label,
                "to_content_id": to_version.content_id,
                "to_label": to_version.label,
                "summary": result.summary(),
                "intent": result.intent,
                "added": result.added,
                "removed": result.removed,
                "unchanged": result.unchanged,
                "old_sentence_count": result.old_count,
                "new_sentence_count": result.new_count,
                "new_sentence_pct": result.new_sentence_pct,
                "removed_sentence_pct": result.removed_sentence_pct,
            }

    def versions(self, token: str | None, project_id: str,
                 limit: int = 50, offset: int = 0) -> dict:
        if not 1 <= limit <= 200:
            raise ApiError(400, "limit must be between 1 and 200")
        if offset < 0:
            raise ApiError(400, "offset must not be negative")
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            page = project.versions[offset:offset + limit]
            return {"versions": [
                {"content_id": v.content_id,
                 "parent_content_id": v.parent_content_id,
                 "actor_id": v.actor_id, "timestamp": v.timestamp,
                 "label": v.label, "filename": v.filename,
                 "content_type": v.content_type, "size": v.size}
                for v in page
            ], "total": len(project.versions), "limit": limit,
                "offset": offset}

    def version_content(self, token: str | None, project_id: str,
                        content_id: str) -> dict:
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            version = next((v for v in project.versions
                            if v.content_id == content_id), None)
            if version is None:
                raise ApiError(404, "version not found")
            return {"content_base64": base64.b64encode(
                project.read(version)).decode()}

    def events(self, token: str | None, project_id: str,
               limit: int = 50, offset: int = 0) -> dict:
        """The project's signed ledger events, newest first, paged."""
        if not 1 <= limit <= 200:
            raise ApiError(400, "limit must be between 1 and 200")
        if offset < 0:
            raise ApiError(400, "offset must not be negative")
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            events = list(reversed(project.ledger.events))
            return {"events": events[offset:offset + limit],
                    "total": len(events), "limit": limit, "offset": offset}

    def export(self, token: str | None, project_id: str,
               claim: str = "") -> dict:
        """A signed evidence bundle for the whole project, downloadable
        over the API. Signed with the caller's own key, so the bundle
        is attributable to the person who exported it."""
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            texts = [project.read(v).decode(errors="replace")
                     for v in project.versions]
            return build_evidence_bundle(
                project, texts, actor.secret_key, actor.public_key, claim,
                contribution_coverage=self._contribution_map(project).coverage(),
                exported_at=_now())

    def verify(self, token: str | None, project_id: str) -> dict:
        with self._lock:
            actor = self._actor_for_token(token)
            project = self._project_for(actor, project_id)
            texts = [project.read(v).decode(errors="replace")
                     for v in project.versions]
            return verification_page(
                project, texts,
                self._contribution_map(project).coverage())

    def verify_bundle(self, bundle) -> dict:
        """Verify a signed evidence bundle. Public: a third party
        checking a dispute needs no account on this server."""
        if not isinstance(bundle, dict):
            raise ApiError(400, "bundle must be a JSON object")
        problems = verify_evidence_bundle(bundle)
        return {"valid": problems == [], "problems": problems}


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
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            if status == 413:
                # The client may still be sending the oversized body;
                # close so it is not parsed as a follow-up request.
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            raw_length = self.headers.get("Content-Length") or "0"
            try:
                length = int(raw_length)
            except ValueError:
                raise ApiError(400, "invalid Content-Length")
            if length < 0:
                raise ApiError(400, "invalid Content-Length")
            if length > MAX_BODY_BYTES:
                # Rejected on headers alone, before the body is read.
                raise ApiError(413, "request body too large")
            if not length:
                return {}
            content_type = self.headers.get("Content-Type") or ""
            if not content_type.startswith("application/json"):
                raise ApiError(415, "Content-Type must be application/json")
            try:
                return json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                raise ApiError(400, "body is not valid JSON")

        def _token(self) -> str | None:
            auth = self.headers.get("Authorization") or ""
            if auth.startswith("Bearer "):
                return auth[7:]
            return None

        def _route(self, method: str, path: str, query: dict, body: dict,
                   remote_addr: str | None = None):
            parts = [p for p in path.split("/") if p]
            token = self._token()
            if method == "GET" and parts == ["api", "health"]:
                return 200, _health()
            if method == "GET" and parts == ["api", "openapi.json"]:
                return 200, OPENAPI_SPEC
            if method == "POST" and parts == ["api", "users"]:
                return 201, app.register(body["username"], body["name"],
                                         body["password"], remote_addr)
            if method == "POST" and parts == ["api", "sessions"]:
                return 200, app.login(body["username"], body["password"],
                                      remote_addr,
                                      self.headers.get("User-Agent"))
            if method == "POST" and parts == ["api", "sessions", "revoke"]:
                return 200, app.logout(token)
            if method == "POST" and parts == ["api", "sessions", "revoke-all"]:
                return 200, app.logout_all(token)
            if method == "GET" and parts == ["api", "sessions", "audit"]:
                return 200, app.audit_for(token)
            if method == "GET" and parts == ["api", "sessions"]:
                return 200, app.sessions_for(token)
            if method == "POST" and parts == ["api", "sessions", "revoke-one"]:
                return 200, app.revoke_session(token, body["session_id"])
            if method == "POST" and parts == ["api", "projects"]:
                return 201, app.create_project(token, body["title"])
            if method == "GET" and parts == ["api", "projects"]:
                return 200, app.list_projects(token, *_parse_paging(query))
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
                                       body.get("filename", ""),
                                       body.get("content_type",
                                                "application/octet-stream"))
            if (method == "POST" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "approvals"):
                return 200, app.approve(token, parts[2], body["content_id"])
            if (method == "POST" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "declarations"):
                return 201, app.declare(
                    token, parts[2], body["content_id"], body["tool"],
                    body.get("prompt_summary", ""),
                    body.get("sentence_indices", []))
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "declarations"):
                return 200, app.declarations(token, parts[2])
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "contributions"):
                return 200, app.contributions(token, parts[2])
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "diff"):
                return 200, app.diff(
                    token, parts[2],
                    query.get("from", [None])[0],
                    query.get("to", [None])[0])
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "versions"):
                return 200, app.versions(token, parts[2],
                                         *_parse_paging(query))
            if (method == "GET" and len(parts) == 5
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "versions" and parts[4] == "content"):
                return 200, app.version_content(
                    token, parts[2], query.get("content_id", [""])[0])
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "events"):
                return 200, app.events(token, parts[2],
                                       *_parse_paging(query))
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "verify"):
                return 200, app.verify(token, parts[2])
            if (method == "GET" and len(parts) == 4
                    and parts[:2] == ["api", "projects"]
                    and parts[3] == "export"):
                return 200, app.export(
                    token, parts[2], query.get("claim", [""])[0])
            if (method == "POST" and parts == ["api", "bundles", "verify"]):
                return 200, app.verify_bundle(body)
            raise ApiError(404, "route not found")

        def _handle(self, method: str) -> None:
            with app.request_context(self.client_address[0],
                                     self.headers.get("User-Agent")):
                try:
                    app.check_request_rate(self.client_address[0])
                    parsed = urlparse(self.path)
                    body = self._read_json() if method == "POST" else {}
                    status, payload = self._route(
                        method, parsed.path, parse_qs(parsed.query), body,
                        self.client_address[0])
                    self._send(status, payload)
                except ApiError as exc:
                    self._send(exc.status, {"error": exc.message})
                except KeyError as exc:
                    self._send(400, {"error": f"missing field: {exc.args[0]}"})
                except Exception as exc:
                    # Never leak internals to the client; log server-side.
                    print(f"internal error: {exc!r}", file=sys.stderr)
                    self._send(500, {"error": "internal error"})

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
