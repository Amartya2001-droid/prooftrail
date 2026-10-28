"""Public verification pages and signed dispute evidence bundles.

The verification page proves a document's history *without* exposing its
private source material: it lists version hashes, actors, timestamps,
signatures and diff summaries — never the content itself.

The evidence bundle is the opposite: for a dispute, the owner exports
everything — original version, diffs, timestamps, contributor history —
signed with their key, so a third party can re-verify every claim.
"""

from __future__ import annotations

import json
from typing import Any

from .crypto import content_id, sign, verify
from .diffing import diff_texts
from .ledger import Ledger
from .store import Project


def self_approvals_for(project: Project) -> list[dict[str, Any]]:
    """Approvals where the approver is the version's own uploader.

    Not rejected — a solo creator legitimately approves their own
    work — but weaker evidence than an independent approval, so both
    the verification page and the evidence bundle name them.
    """
    by_id = {v.content_id: v for v in project.history()}
    found = []
    for event in project.ledger.events:
        if event["type"] != "approval":
            continue
        version = by_id.get(event.get("content_id"))
        if version is not None and version.actor_id == event["actor"]:
            found.append({
                "label": version.label,
                "content_id": version.content_id,
                "actor": event["actor"],
            })
    return found


def verification_page(
    project: Project,
    texts: list[str],
    contribution_coverage: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Shareable summary of a project's history. No source text included."""
    versions = project.history()
    chain = []
    for i, version in enumerate(versions):
        entry: dict[str, Any] = {
            "label": version.label,
            "content_id": version.content_id,
            "parent_content_id": version.parent_content_id,
            "actor": version.actor_id,
            "timestamp": version.timestamp,
        }
        if i:
            entry["change"] = diff_texts(texts[i - 1], texts[i]).summary()
        chain.append(entry)
    # Self-approvals are not rejected — a solo creator legitimately
    # approves their own work — but they are weaker evidence than an
    # independent approval, so the page names them explicitly instead
    # of letting them pass as ordinary approvals.
    return {
        "project_id": project.project_id,
        "title": project.title,
        "ledger_valid": project.verify() == [],
        "ledger_problems": project.verify(),
        "versions": chain,
        "self_approvals": self_approvals_for(project),
        "contributors": [
            {"actor_id": a.actor_id, "name": a.name,
             "public_key": a.public_key.hex()}
            for a in project.collaborators.values()
        ],
        "events": len(project.ledger.events),
        "contribution_coverage_pct": contribution_coverage or {},
    }


def build_evidence_bundle(
    project: Project,
    texts: list[str],
    owner_secret: bytes,
    owner_public: bytes,
    claim: str = "",
    contribution_coverage: dict[str, float] | None = None,
    exported_at: str | None = None,
) -> dict[str, Any]:
    """Build a signed bundle for a dispute: content, diffs, history.

    A bundle must stand on its own for a third party: besides the
    versions and diffs it carries the AI declarations, the Human
    Contribution Map coverage, the self-approval flags, every
    collaborator's public key (so the embedded ledger chain can be
    re-verified without an account), and a server-assigned export
    timestamp. All of it is covered by the owner's signature.
    """
    from datetime import datetime, timezone

    versions = project.history()
    bundle: dict[str, Any] = {
        "project_id": project.project_id,
        "title": project.title,
        "claim": claim,
        "exported_at": exported_at or datetime.now(timezone.utc).isoformat(),
        "versions": [
            {
                "label": v.label,
                "content_id": v.content_id,
                "parent_content_id": v.parent_content_id,
                "actor": v.actor_id,
                "timestamp": v.timestamp,
                "content": texts[i],
            }
            for i, v in enumerate(versions)
        ],
        "diffs": [
            diff_texts(texts[i - 1], texts[i]).summary()
            for i in range(1, len(texts))
        ],
        "declarations": [
            {"version_label": d.version_label, "actor_id": d.actor_id,
             "tool": d.tool, "prompt_summary": d.prompt_summary,
             "sentence_indices": d.sentence_indices}
            for d in project.declarations()
        ],
        "contribution_coverage_pct": contribution_coverage or {},
        "self_approvals": self_approvals_for(project),
        "actor_public_keys": {
            a.actor_id: a.public_key.hex()
            for a in project.collaborators.values()
        },
        "ledger_events": project.ledger.events,
        "ledger_valid_at_export": project.verify() == [],
    }
    payload = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    bundle["owner_signature"] = sign(owner_secret, owner_public, payload).hex()
    bundle["owner_public_key"] = owner_public.hex()
    return bundle


def verify_evidence_bundle(bundle: dict[str, Any]) -> list[str]:
    """Re-verify a bundle. Returns problems (empty = fully verified).

    The owner's signature proves who exported the bundle, not that
    its history is genuine — a malicious exporter could re-sign a
    bundle with forged events. So verification also replays the
    embedded ledger chain against the bundled actor public keys, and
    checks version parent linkage, independently of the signature.
    """
    problems: list[str] = []
    signature = bundle.get("owner_signature", "")
    public_hex = bundle.get("owner_public_key", "")
    unsigned = {k: v for k, v in bundle.items()
                if k not in ("owner_signature", "owner_public_key")}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    try:
        public = bytes.fromhex(public_hex)
        if not verify(public, payload, bytes.fromhex(signature)):
            problems.append("owner signature invalid")
    except Exception:
        problems.append("owner signature unreadable")
    for version in bundle.get("versions", []):
        if content_id(version["content"].encode()) != version["content_id"]:
            problems.append(
                f"version {version['label']}: content does not match its hash"
            )
    versions = bundle.get("versions", [])
    for i, version in enumerate(versions):
        expected_parent = versions[i - 1]["content_id"] if i else None
        if version.get("parent_content_id") != expected_parent:
            problems.append(
                f"version {version['label']}: parent linkage broken")
    actor_keys = bundle.get("actor_public_keys")
    if not isinstance(actor_keys, dict) or not actor_keys:
        problems.append(
            "bundle does not include actor public keys; "
            "ledger chain cannot be re-verified")
        return problems
    ledger = Ledger(bundle.get("project_id", ""))
    keys_ok = True
    for actor_id, key_hex in actor_keys.items():
        try:
            ledger.register_actor(actor_id, bytes.fromhex(key_hex))
        except Exception:
            problems.append(f"actor public key unreadable for {actor_id}")
            keys_ok = False
    if keys_ok:
        ledger.events = bundle.get("ledger_events", [])
        problems.extend(f"ledger: {p}" for p in ledger.verify())
    return problems
