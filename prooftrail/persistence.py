"""Disk persistence for ProofTrail state, as plain JSON.

What is stored: user records (salts, verifier, public key — never a
signing secret), project blobs (base64), version chains, ledger events
and collaborator public keys. Signing secrets are re-derived from the
password at login, so a stolen data file cannot forge history.

Loaded collaborators carry an empty secret placeholder; the server
replaces it with the real, login-derived actor before any signing call.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from .auth import UserRecord
from .ledger import Ledger
from .store import Actor, Project, Version


def project_to_dict(project: Project) -> dict:
    return {
        "project_id": project.project_id,
        "title": project.title,
        "blobs": {cid: base64.b64encode(data).decode()
                  for cid, data in project._blobs.items()},
        "versions": [
            {
                "content_id": v.content_id,
                "parent_content_id": v.parent_content_id,
                "actor_id": v.actor_id,
                "timestamp": v.timestamp,
                "label": v.label,
            }
            for v in project.versions
        ],
        "events": project.ledger.events,
        "collaborators": [
            {"actor_id": a.actor_id, "name": a.name,
             "public_key": a.public_key.hex()}
            for a in project.collaborators.values()
        ],
    }


def project_from_dict(data: dict) -> Project:
    project = Project(data["project_id"], data["title"])
    project._blobs = {cid: base64.b64decode(b)
                      for cid, b in data["blobs"].items()}
    project.versions = [Version(**v) for v in data["versions"]]
    ledger = Ledger(data["project_id"])
    ledger.events = data["events"]
    project.ledger = ledger
    for collab in data["collaborators"]:
        actor = Actor(collab["actor_id"], collab["name"], b"",
                      bytes.fromhex(collab["public_key"]))
        project.collaborators[actor.actor_id] = actor
        ledger.register_actor(actor.actor_id, actor.public_key)
    return project


def save_state(path: str | Path, users: dict, projects: dict) -> None:
    state = {
        "users": {name: user.to_dict() for name, user in users.items()},
        "projects": {pid: project_to_dict(p) for pid, p in projects.items()},
    }
    Path(path).write_text(json.dumps(state, indent=2, sort_keys=True))


def load_state(path: str | Path) -> tuple[dict, dict]:
    """Load state; a missing file means a fresh, empty state."""
    file = Path(path)
    if not file.exists():
        return {}, {}
    state = json.loads(file.read_text())
    users = {name: UserRecord.from_dict(rec)
             for name, rec in state.get("users", {}).items()}
    projects = {pid: project_from_dict(p)
                for pid, p in state.get("projects", {}).items()}
    return users, projects
