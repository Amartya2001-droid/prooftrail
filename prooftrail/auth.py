"""Authentication for ProofTrail's week-1 API.

Design decision, stated plainly: an actor's Ed25519 signing key is
*derived from their password* (PBKDF2, separate salts for the login
verifier and for the key). That means:

- the server never stores a signing secret — only salts, a verifier hash
  and the public key — so a stolen database cannot forge ledger events;
- logging in from any machine re-derives the same key, so the same actor
  can keep signing the same ledger;
- losing the password loses the key, which is the honest trade-off of
  this design (key recovery is a week-3 concern, not a silent backdoor).

Sessions are opaque random tokens held in memory only.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .crypto import public_key_from_secret

_ITERATIONS = 200_000
SESSION_TTL_SECONDS = 24 * 3600
# Idle sessions die sooner than the absolute expiry: half an hour
# without a request ends the session even inside the 24-hour window,
# so a token left on a shared or stolen machine has a short life.
IDLE_TIMEOUT_SECONDS = 30 * 60


def _pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)


@dataclass
class UserRecord:
    username: str
    name: str
    actor_id: str
    salt_auth: bytes = field(repr=False)
    salt_key: bytes = field(repr=False)
    verifier: bytes = field(repr=False)
    public_key: bytes

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "name": self.name,
            "actor_id": self.actor_id,
            "salt_auth": self.salt_auth.hex(),
            "salt_key": self.salt_key.hex(),
            "verifier": self.verifier.hex(),
            "public_key": self.public_key.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "UserRecord":
        return cls(
            username=data["username"],
            name=data["name"],
            actor_id=data["actor_id"],
            salt_auth=bytes.fromhex(data["salt_auth"]),
            salt_key=bytes.fromhex(data["salt_key"]),
            verifier=bytes.fromhex(data["verifier"]),
            public_key=bytes.fromhex(data["public_key"]),
        )


# Passwords seen in breach lists and credential-stuffing dictionaries.
# Checked case-insensitively at registration. This is a registration
# boundary rule, not a property of create_user: low-level callers and
# tests construct records directly, and the policy lives where accounts
# are actually created.
COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "password1234", "passw0rd",
    "12345678", "123456789", "1234567890", "123123", "111111", "000000",
    "qwerty", "qwerty123", "abc123", "letmein1", "welcome", "welcome1",
    "admin", "admin123", "monkey", "dragon", "football", "baseball",
    "sunshine", "master", "shadow", "superman", "trustno1", "iloveyou",
    "princess", "solo", "starwars", "whatever", "freedom", "hello123",
    "charlie", "aa123456", "changeme", "secret123", "hunter123",
})


def validate_password(username: str, password: str) -> None:
    """Enforce the registration password policy. Raises ValueError."""
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        raise ValueError("password is too common")
    if lowered == username.lower():
        raise ValueError("password must not be the username")


def create_user(username: str, name: str, password: str) -> UserRecord:
    """Create a user record. Returns the record (never the password)."""
    salt_auth = secrets.token_bytes(16)
    salt_key = secrets.token_bytes(16)
    secret = _pbkdf2(password, salt_key)
    return UserRecord(
        username=username,
        name=name,
        actor_id=username,
        salt_auth=salt_auth,
        salt_key=salt_key,
        verifier=_pbkdf2(password, salt_auth),
        public_key=public_key_from_secret(secret),
    )


def authenticate(user: UserRecord, password: str) -> bytes | None:
    """Check a password. On success return the derived signing secret."""
    if not hmac.compare_digest(_pbkdf2(password, user.salt_auth), user.verifier):
        return None
    return _pbkdf2(password, user.salt_key)


# Fixed dummy values for the unknown-user path. They are not secrets:
# their only job is to make rejecting an unknown username cost the
# same PBKDF2 work as rejecting a wrong password for a real user.
_DUMMY_SALT = bytes(16)
_DUMMY_VERIFIER = bytes(32)


@dataclass
class AuditEvent:
    """One authentication event. Kept in memory only, like sessions:
    a restart clears the trail, which is the honest trade-off of not
    adding a second store for it."""

    timestamp: float
    event: str
    actor_id: str | None
    remote_addr: str | None
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": datetime.fromtimestamp(
                self.timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": self.event,
            "actor_id": self.actor_id,
            "remote_addr": self.remote_addr,
            "detail": self.detail,
        }


class AuditLog:
    """Capped, newest-first-queried log of authentication events.

    Each user sees only their own events: the trail is evidence for
    the account holder ("was that login me?"), not a window into
    other accounts.
    """

    def __init__(self, max_events: int = 1000,
                 time_fn=time.time) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=max_events)
        self._now = time_fn

    def record(self, event: str, actor_id: str | None,
               remote_addr: str | None = None, detail: str = "") -> None:
        self._events.append(AuditEvent(self._now(), event, actor_id,
                                       remote_addr, detail))

    def events_for(self, actor_id: str) -> list[dict]:
        return [e.to_dict() for e in reversed(self._events)
                if e.actor_id == actor_id]


def authenticate_unknown(password: str) -> None:
    """Burn the same password-checking work as a failed login.

    Without this, an unknown username is rejected immediately while a
    known username pays for a 200,000-iteration PBKDF2 first, and the
    timing difference alone enumerates accounts despite the generic
    error message. Always returns None.
    """
    candidate = _pbkdf2(password, _DUMMY_SALT)
    hmac.compare_digest(candidate, _DUMMY_VERIFIER)
    return None


@dataclass
class SessionRecord:
    """One login session: who, when it dies, and what client it
    belongs to. The token itself is the dict key and is never stored
    inside the record or exposed by session listings."""

    actor_id: str
    expires_at: float
    created_at: float
    last_seen: float
    session_id: str
    remote_addr: str | None
    user_agent: str | None
    label: str


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


class SessionStore:
    """In-memory token -> actor_id sessions with expiry.

    Tokens expire after ``ttl_seconds`` (default 24h). ``time_fn`` exists
    so tests can control the clock; production uses ``time.time``.

    A session created with a client address and user agent is bound to
    them: a later request presenting the token from a different address
    or agent has the token revoked on the spot instead of being served.
    Sessions created without that information (in-process callers) are
    unbound, and lookups without it skip the check, so the binding
    only bites where the HTTP layer actually knows the client.
    """

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS,
                 idle_seconds: int = IDLE_TIMEOUT_SECONDS,
                 time_fn=time.time) -> None:
        self._ttl = ttl_seconds
        self._idle = idle_seconds
        self._now = time_fn
        self._sessions: dict[str, SessionRecord] = {}

    def create(self, actor_id: str, remote_addr: str | None = None,
               user_agent: str | None = None) -> str:
        token = secrets.token_urlsafe(32)
        now = self._now()
        self._sessions[token] = SessionRecord(
            actor_id=actor_id, expires_at=now + self._ttl,
            created_at=now, last_seen=now,
            session_id=secrets.token_hex(8),
            remote_addr=remote_addr, user_agent=user_agent,
            label=(user_agent or "unknown device")[:100])
        return token

    def lookup(self, token: str | None, remote_addr: str | None = None,
               user_agent: str | None = None) -> str | None:
        if not token:
            return None
        entry = self._sessions.get(token)
        if entry is None:
            return None
        now = self._now()
        if now >= entry.expires_at:
            self._sessions.pop(token, None)
            return None
        # Idle expiry is checked before the binding checks and before
        # last_seen is refreshed: an idle session is dead, and a
        # request arriving after the idle window must not revive it.
        if now - entry.last_seen >= self._idle:
            self._sessions.pop(token, None)
            return None
        # A bound session presented from elsewhere is stolen until
        # proven otherwise: revoke it rather than merely rejecting
        # this one request, so the token cannot be retried.
        if (entry.remote_addr is not None and remote_addr is not None
                and remote_addr != entry.remote_addr):
            self._sessions.pop(token, None)
            return None
        if (entry.user_agent is not None and user_agent is not None
                and user_agent != entry.user_agent):
            self._sessions.pop(token, None)
            return None
        entry.last_seen = now
        return entry.actor_id

    def revoke(self, token: str) -> None:
        self._sessions.pop(token, None)

    def record_for_token(self, token: str | None) -> SessionRecord | None:
        """The session record behind a token, if it is still live.
        Used to mark the caller's own session in listings; it performs
        no expiry or binding checks, so callers must validate first."""
        if not token:
            return None
        return self._sessions.get(token)

    def list_sessions(self, actor_id: str) -> list[dict]:
        """Session metadata for one actor, newest first. Tokens are
        never included: the session_id is the handle for revocation,
        and it is useless without the token itself."""
        records = [rec for rec in self._sessions.values()
                   if rec.actor_id == actor_id]
        records.sort(key=lambda rec: rec.created_at, reverse=True)
        return [{
            "session_id": rec.session_id,
            "created_at": _iso(rec.created_at),
            "last_seen": _iso(rec.last_seen),
            "expires_at": _iso(rec.expires_at),
            "remote_addr": rec.remote_addr,
            "user_agent": rec.user_agent,
            "label": rec.label,
        } for rec in records]

    def revoke_session(self, actor_id: str,
                       session_id: str) -> str | None:
        """Revoke one session by its id. Returns the revoked token so
        the server can drop its signing secret, or None when no such
        session belongs to this actor."""
        for token, rec in self._sessions.items():
            if rec.actor_id == actor_id and rec.session_id == session_id:
                self._sessions.pop(token, None)
                return token
        return None

    def revoke_all(self, actor_id: str) -> list[str]:
        """Revoke every session for one actor (lost-device case).
        Returns the revoked tokens so the server can drop their
        signing secrets too."""
        revoked = [t for t, rec in self._sessions.items()
                   if rec.actor_id == actor_id]
        for token in revoked:
            self._sessions.pop(token, None)
        return revoked

    def prune(self) -> None:
        now = self._now()
        expired = [t for t, rec in self._sessions.items()
                   if now >= rec.expires_at]
        for token in expired:
            self._sessions.pop(token, None)
