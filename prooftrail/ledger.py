"""Immutable, hash-chained, signed event ledger.

Every event carries its index, type, actor, the content it refers to, its
parent version, a timestamp, the hash of the previous event, and an Ed25519
signature over all of that. Rewriting any event — or dropping one from the
middle — breaks the chain hash, the signature, or both, so ``verify()``
catches it.

The ledger is deliberately storage-agnostic: events are plain dicts, so they
can be persisted as JSON rows, files, or database records.
"""

from __future__ import annotations

import json
from typing import Any

from .crypto import sha256_hex, sign, verify


def canonical(event: dict) -> bytes:
    """Canonical JSON encoding of an event, minus signature and hash."""
    unsigned = {k: v for k, v in event.items() if k not in ("signature", "hash")}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()


def event_hash(event: dict) -> str:
    return sha256_hex(canonical(event))


class Ledger:
    """An append-only chain of signed events for one project."""

    def __init__(self, project_id: str) -> None:
        self.project_id = project_id
        self.events: list[dict] = []
        self._public_keys: dict[str, bytes] = {}

    def register_actor(self, actor_id: str, public_key: bytes) -> None:
        self._public_keys[actor_id] = public_key

    def append(
        self,
        event_type: str,
        actor_id: str,
        secret_key: bytes,
        content_id: str | None = None,
        parent_content_id: str | None = None,
        timestamp: str = "",
        payload: dict | None = None,
    ) -> dict:
        """Append a signed event. Returns the event dict."""
        public = self._public_keys.get(actor_id)
        if public is None:
            raise ValueError(f"unknown actor: {actor_id}")
        prev = self.events[-1]["hash"] if self.events else "0" * 64
        event: dict[str, Any] = {
            "project_id": self.project_id,
            "index": len(self.events),
            "type": event_type,
            "actor": actor_id,
            "content_id": content_id,
            "parent_content_id": parent_content_id,
            "timestamp": timestamp,
            "prev_hash": prev,
            "payload": payload or {},
        }
        event["signature"] = sign(secret_key, public, canonical(event)).hex()
        event["hash"] = event_hash(event)
        self.events.append(event)
        return event

    def verify(self) -> list[str]:
        """Verify the whole chain. Returns a list of problems (empty = valid)."""
        problems: list[str] = []
        prev = "0" * 64
        for i, event in enumerate(self.events):
            if event["index"] != i:
                problems.append(f"event {i}: index mismatch")
            if event["prev_hash"] != prev:
                problems.append(f"event {i}: prev_hash does not match prior event")
            stored = event["hash"]
            if event_hash(event) != stored:
                problems.append(f"event {i}: hash mismatch (content tampered)")
            public = self._public_keys.get(event["actor"])
            if public is None:
                problems.append(f"event {i}: unknown actor {event['actor']}")
            elif not verify(public, canonical(event), bytes.fromhex(event["signature"])):
                problems.append(f"event {i}: signature invalid")
            prev = stored
        return problems

    def to_json(self) -> str:
        return json.dumps(self.events, indent=2, sort_keys=True)
