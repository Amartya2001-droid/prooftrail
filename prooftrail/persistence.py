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
import os
import shutil
import sys
import tempfile
from pathlib import Path

from .auth import UserRecord
from .ledger import Ledger
from .store import Actor, Project, Version


def project_to_dict(project: Project) -> dict:
    return {
        "project_id": project.project_id,
        "title": project.title,
        "creator_id": project.creator_id,
        "blobs": {cid: base64.b64encode(data).decode()
                  for cid, data in project._blobs.items()},
        "versions": [
            {
                "content_id": v.content_id,
                "parent_content_id": v.parent_content_id,
                "actor_id": v.actor_id,
                "timestamp": v.timestamp,
                "label": v.label,
                "filename": v.filename,
                "content_type": v.content_type,
                "size": v.size,
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
    # States written before creator tracking default to the first
    # collaborator, who was the creator by construction.
    project.creator_id = data.get("creator_id") or (
        next(iter(project.collaborators), None))
    return project


def save_state(path: str | Path, users: dict, projects: dict) -> None:
    """Save atomically, with owner-only permissions.

    The file holds password verifiers (PBKDF2 hashes, not passwords),
    so it must not be world-readable — and a crash mid-write must not
    leave a half-written state file behind. Write to a temp file in the
    same directory, restrict it, then rename over the destination.

    Before replacing an existing state file, the previous copy is kept
    as ``<path>.bak`` (also 0600). That backup is the fallback
    ``load_state`` uses when the main file is corrupt or fails
    verification, so one bad write or one tampered file cannot destroy
    the last known-good history.
    """
    state = {
        "users": {name: user.to_dict() for name, user in users.items()},
        "projects": {pid: project_to_dict(p) for pid, p in projects.items()},
    }
    target = Path(path)
    if target.exists():
        backup = Path(str(target) + ".bak")
        shutil.copy2(target, backup)
        os.chmod(backup, 0o600)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-state-")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(state, indent=2, sort_keys=True))
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _load_one(file: Path) -> tuple[dict, dict]:
    """Read and verify a single state file. Raises ValueError if the
    file is corrupt JSON or any project fails verification."""
    try:
        state = json.loads(file.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"state file is corrupt: {exc}") from exc
    users = {name: UserRecord.from_dict(rec)
             for name, rec in state.get("users", {}).items()}
    projects = {pid: project_from_dict(p)
                for pid, p in state.get("projects", {}).items()}
    for pid, project in projects.items():
        problems = project.verify()
        if problems:
            raise ValueError(
                f"state file failed verification for project {pid}: "
                + "; ".join(problems[:3]))
    return users, projects


def load_state(path: str | Path) -> tuple[dict, dict]:
    """Load state; a missing file means a fresh, empty state.

    Every loaded project is fully verified before it is returned: a
    data file whose ledger chain, signatures, version linkage or blob
    store has been tampered with is refused outright, so a corrupted
    or doctored state file can never be served as if it were valid
    history. If the main file is unusable but a previous-good backup
    (``<path>.bak``) loads and verifies, the backup is returned
    instead; if both fail, the error from the main file is raised.
    """
    file = Path(path)
    if not file.exists():
        return {}, {}
    try:
        return _load_one(file)
    except ValueError as main_error:
        backup = Path(str(file) + ".bak")
        if backup.exists():
            try:
                users, projects = _load_one(backup)
            except ValueError:
                raise main_error from None
            print(f"warning: state file {file} unusable "
                  f"({main_error}); loaded backup {backup}",
                  file=sys.stderr)
            return users, projects
        raise
