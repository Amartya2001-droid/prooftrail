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
from dataclasses import dataclass, field

from .crypto import public_key_from_secret

_ITERATIONS = 200_000


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


class SessionStore:
    """In-memory token -> actor_id sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, str] = {}

    def create(self, actor_id: str) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = actor_id
        return token

    def lookup(self, token: str | None) -> str | None:
        if not token:
            return None
        return self._sessions.get(token)

    def revoke(self, token: str) -> None:
        self._sessions.pop(token, None)
