"""Projects, versions and actors.

A project owns a content-addressed store (content_id -> bytes) and a
signed ledger. Uploading a version stores the bytes under their SHA-256
address, links the version to its parent, and appends a signed ledger
event — so the version history and the audit trail are the same object,
not two systems that can drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import content_id, generate_keypair
from .ledger import Ledger


@dataclass
class Actor:
    actor_id: str
    name: str
    secret_key: bytes = field(repr=False)
    public_key: bytes

    @classmethod
    def create(cls, actor_id: str, name: str) -> "Actor":
        secret, public = generate_keypair()
        return cls(actor_id, name, secret, public)


@dataclass
class Version:
    content_id: str
    parent_content_id: str | None
    actor_id: str
    timestamp: str
    label: str = ""


class Project:
    """A single ProofTrail project: files, versions, ledger."""

    def __init__(self, project_id: str, title: str) -> None:
        self.project_id = project_id
        self.title = title
        self.ledger = Ledger(project_id)
        self._blobs: dict[str, bytes] = {}
        self.versions: list[Version] = []
        self.collaborators: dict[str, Actor] = {}

    def add_collaborator(self, actor: Actor) -> None:
        self.collaborators[actor.actor_id] = actor
        self.ledger.register_actor(actor.actor_id, actor.public_key)

    def upload(
        self,
        actor: Actor,
        data: bytes,
        timestamp: str,
        label: str = "",
    ) -> Version:
        """Store a new version and record it on the ledger."""
        if actor.actor_id not in self.collaborators:
            raise ValueError(f"{actor.actor_id} is not a collaborator")
        cid = content_id(data)
        parent = self.versions[-1].content_id if self.versions else None
        self._blobs[cid] = data
        version = Version(cid, parent, actor.actor_id, timestamp, label)
        self.versions.append(version)
        event_type = "upload" if parent is None else "edit"
        self.ledger.append(
            event_type, actor.actor_id, actor.secret_key,
            content_id=cid, parent_content_id=parent, timestamp=timestamp,
            payload={"label": label},
        )
        return version

    def approve(self, actor: Actor, version: Version, timestamp: str) -> dict:
        """Record a client/collaborator approval of a version."""
        if actor.actor_id not in self.collaborators:
            raise ValueError(f"{actor.actor_id} is not a collaborator")
        return self.ledger.append(
            "approval", actor.actor_id, actor.secret_key,
            content_id=version.content_id, timestamp=timestamp,
        )

    def read(self, version: Version) -> bytes:
        return self._blobs[version.content_id]

    def history(self) -> list[Version]:
        return list(self.versions)

    def verify(self) -> list[str]:
        """Verify ledger chain plus version/parent consistency."""
        problems = self.ledger.verify()
        for i, version in enumerate(self.versions):
            expected_parent = self.versions[i - 1].content_id if i else None
            if version.parent_content_id != expected_parent:
                problems.append(f"version {i}: parent linkage broken")
            if version.content_id not in self._blobs:
                problems.append(f"version {i}: content missing from store")
        return problems
