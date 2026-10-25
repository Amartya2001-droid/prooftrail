# ProofTrail

An AI-powered provenance and dispute engine for digital work.

ProofTrail continuously verifies who created what, when, how it changed, and
whether an AI touched it — then turns that evidence into a tamper-evident,
shareable "proof trail". It does not ask "Was this made by AI?", which is
unreliable. It answers the defensible question: "Here is the complete,
verifiable history of this work."

## Core ideas

- **Immutable change ledger** — every upload, edit, approval and export is a
  signed event with a SHA-256 hash, timestamp, actor and parent version.
  Events are hash-chained, so rewriting history breaks verification.
- **Semantic version diffing** — what changed, how much changed, and what
  kind of change it was (rewrite, expansion, tightening, restructure...).
- **AI-involvement transparency** — creators voluntarily declare prompts and
  tools; the system correlates declarations with detected changes and
  reports confidence plus evidence, never a false binary verdict.
- **Human Contribution Map** — a per-segment view of a document showing
  which portions are human-written, AI-assisted, imported or externally
  contributed.
- **Public verification page data** — a shareable summary of a document's
  history, signatures and contributors, without exposing private source
  material.
- **Dispute mode** — a signed evidence bundle (original version, diffs,
  timestamps, contributor history) exportable for a plagiarism or
  unauthorised-edit claim.

## Tech

Pure Python 3 standard library only — no third-party dependencies. The
Ed25519 implementation is a compact, self-contained RFC 8032 implementation
so the trust layer works anywhere Python runs.

## Layout

- `prooftrail/crypto.py` — SHA-256 content addressing, Ed25519 sign/verify
- `prooftrail/ledger.py` — hash-chained signed event ledger
- `prooftrail/store.py` — projects, versions, actors
- `prooftrail/diffing.py` — semantic diff, change stats, intent
- `prooftrail/contributions.py` — AI declarations, contribution map
- `prooftrail/verification.py` — verification page data, evidence bundles
- `demo/` — the freelance-designer v1 -> v2 -> v3 scenario

## Run the tests

```sh
python3 -m unittest discover -s tests -v
```

## Run the demo

```sh
python3 demo/designer_scenario.py
```

## Week 1: HTTP API (auth, projects, file upload, version history)

```sh
python3 -m prooftrail.server --port 8000 --data prooftrail-data.json
sh demo/api_demo.sh 8000   # needs curl and jq
```

Endpoints (JSON; project routes need `Authorization: Bearer <token>`):

- `POST /api/users` — register `{username, name, password}`
- `POST /api/sessions` — log in, receive a token
- `POST /api/projects` — create a project
- `POST /api/projects/<id>/collaborators` — add a collaborator
- `POST /api/projects/<id>/uploads` — upload a version
  (`{content_base64, label?, timestamp?}`); the server hashes the
  content, links it to its parent, and signs a ledger event
- `POST /api/projects/<id>/approvals` — approve a version
- `GET /api/projects/<id>/versions` — version history
- `GET /api/projects/<id>/versions/content?content_id=sha256:...`
- `GET /api/projects/<id>/verify` — verification page data (hashes only)

Auth design: an actor's Ed25519 signing key is derived from their
password (PBKDF2, separate salts for login check and key). The server
stores salts, a verifier and the public key — never a signing secret —
so a stolen data file cannot forge ledger events. State persists to a
JSON file; sessions live in memory only.
