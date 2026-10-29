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
from dataclasses import dataclass, field

from .crypto import public_key_from_secret

_ITERATIONS = 200_000
SESSION_TTL_SECONDS = 24 * 3600


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


class SessionStore:
    """In-memory token -> actor_id sessions with expiry.

    Tokens expire after ``ttl_seconds`` (default 24h). ``time_fn`` exists
    so tests can control the clock; production uses ``time.time``.
    """

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS,
                 time_fn=time.time) -> None:
        self._ttl = ttl_seconds
        self._now = time_fn
        self._sessions: dict[str, tuple[str, float]] = {}

    def create(self, actor_id: str) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = (actor_id, self._now() + self._ttl)
        return token

    def lookup(self, token: str | None) -> str | None:
        if not token:
            return None
        entry = self._sessions.get(token)
        if entry is None:
            return None
        actor_id, expires_at = entry
        if self._now() >= expires_at:
            self._sessions.pop(token, None)
            return None
        return actor_id

    def revoke(self, token: str) -> None:
        self._sessions.pop(token, None)

    def revoke_all(self, actor_id: str) -> list[str]:
        """Revoke every session for one actor (lost-device case).
        Returns the revoked tokens so the server can drop their
        signing secrets too."""
        revoked = [t for t, (owner, _) in self._sessions.items()
                   if owner == actor_id]
        for token in revoked:
            self._sessions.pop(token, None)
        return revoked

    def prune(self) -> None:
        now = self._now()
        expired = [t for t, (_, exp) in self._sessions.items() if now >= exp]
        for token in expired:
            self._sessions.pop(token, None)
