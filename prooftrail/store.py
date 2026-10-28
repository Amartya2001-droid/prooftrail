"""Projects, versions and actors.

A project owns a content-addressed store (content_id -> bytes) and a
signed ledger. Uploading a version stores the bytes under their SHA-256
address, links the version to its parent, and appends a signed ledger
event — so the version history and the audit trail are the same object,
not two systems that can drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .contributions import Declaration, split_sentences
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
    filename: str = ""
    content_type: str = "application/octet-stream"
    size: int = 0


class Project:
    """A single ProofTrail project: files, versions, ledger."""

    def __init__(self, project_id: str, title: str) -> None:
        self.project_id = project_id
        self.title = title
        self.ledger = Ledger(project_id)
        self._blobs: dict[str, bytes] = {}
        self.versions: list[Version] = []
        self.collaborators: dict[str, Actor] = {}
        # Who may invite new collaborators: the first collaborator
        # added (the creator). Set explicitly by the server, or
        # inferred from the first add for direct store use.
        self.creator_id: str | None = None

    def add_collaborator(self, actor: Actor) -> None:
        if self.creator_id is None:
            self.creator_id = actor.actor_id
        self.collaborators[actor.actor_id] = actor
        self.ledger.register_actor(actor.actor_id, actor.public_key)

    def upload(
        self,
        actor: Actor,
        data: bytes,
        timestamp: str,
        label: str = "",
        filename: str = "",
        content_type: str = "application/octet-stream",
    ) -> Version:
        """Store a new version and record it on the ledger."""
        if actor.actor_id not in self.collaborators:
            raise ValueError(f"{actor.actor_id} is not a collaborator")
        cid = content_id(data)
        parent = self.versions[-1].content_id if self.versions else None
        self._blobs[cid] = data
        version = Version(cid, parent, actor.actor_id, timestamp, label,
                          filename=filename, content_type=content_type,
                          size=len(data))
        self.versions.append(version)
        event_type = "upload" if parent is None else "edit"
        self.ledger.append(
            event_type, actor.actor_id, actor.secret_key,
            content_id=cid, parent_content_id=parent, timestamp=timestamp,
            payload={"label": label, "filename": filename,
                     "size": len(data)},
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

    def declare(self, actor: Actor, version: Version, tool: str,
                prompt_summary: str = "",
                sentence_indices: list[int] | None = None,
                timestamp: str = "") -> dict:
        """Record a voluntary AI-use declaration for a version.

        Declarations live on the signed ledger, not in a side table, so
        they are tamper-evident like every other project event: editing
        or dropping one breaks the chain. ``sentence_indices`` names the
        sentences of the new version the declaration covers; empty means
        all sentences added in this version.
        """
        if actor.actor_id not in self.collaborators:
            raise ValueError(f"{actor.actor_id} is not a collaborator")
        if version.content_id not in {v.content_id for v in self.versions}:
            raise ValueError("version does not belong to this project")
        if not tool.strip() or len(tool) > 100:
            raise ValueError("tool must be 1-100 characters")
        if len(prompt_summary) > 500:
            raise ValueError("prompt_summary must be at most 500 characters")
        indices = list(sentence_indices or [])
        if any(not isinstance(i, int) or isinstance(i, bool) for i in indices):
            raise ValueError("sentence_indices must be integers")
        text = self.read(version).decode(errors="replace")
        sentence_count = len(split_sentences(text))
        if any(i < 0 or i >= sentence_count for i in indices):
            raise ValueError("sentence_indices out of range for this version")
        return self.ledger.append(
            "declaration", actor.actor_id, actor.secret_key,
            content_id=version.content_id, timestamp=timestamp,
            payload={"label": version.label, "tool": tool,
                     "prompt_summary": prompt_summary,
                     "sentence_indices": indices},
        )

    def declarations(self) -> list[Declaration]:
        """Declarations reconstructed from the ledger, in order."""
        found = []
        for event in self.ledger.events:
            if event["type"] != "declaration":
                continue
            payload = event.get("payload", {})
            found.append(Declaration(
                version_label=payload.get("label", ""),
                actor_id=event["actor"],
                tool=payload.get("tool", ""),
                prompt_summary=payload.get("prompt_summary", ""),
                sentence_indices=list(payload.get("sentence_indices", [])),
            ))
        return found

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
