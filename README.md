# ProofTrail

[![CI](https://github.com/Amartya2001-droid/prooftrail/actions/workflows/ci.yml/badge.svg)](https://github.com/Amartya2001-droid/prooftrail/actions/workflows/ci.yml)

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

## Supabase backend (optional)

The JSON file store is the default. To persist state in Supabase
instead, create this table in your project, then start the server
with the backend flag. The service key is server-side only and must
never ship to a client.

```sql
CREATE TABLE IF NOT EXISTS prooftrail_state (id text PRIMARY KEY, state jsonb);
```

```sh
PROOFTRAIL_STATE_BACKEND=supabase SUPABASE_URL=https://<project-ref>.supabase.co SUPABASE_SERVICE_KEY=<secret-key> python3 -m prooftrail.server
```

The server loads the row on startup (verified exactly like a file
load) and saves to it on every change. Transient failures (429,
5xx, network errors) retry up to three times with backoff; anything
else fails loudly instead of being silently dropped.

## Week 1: HTTP API (auth, projects, file upload, version history)

```sh
python3 -m prooftrail.server --port 8000 --data prooftrail-data.json
sh demo/api_demo.sh 8000   # needs curl and jq
```

Endpoints (JSON; project routes need `Authorization: Bearer <token>`).
Full machine-readable spec at `GET /api/openapi.json`; a thin Python
client lives in `prooftrail/client.py`.

- `GET /api/health` — liveness check, no auth
- `POST /api/users` — register `{username, name, password}`
  (username 3–32 chars: letters, digits, `_`, `-`, `.`; password ≥ 8)
- `POST /api/sessions` — log in, receive a token
- `POST /api/sessions/revoke` — log out
- `POST /api/sessions/revoke-all` — log out everywhere (lost-device case)
- `POST /api/projects` — create a project
- `GET /api/projects` — list the projects you collaborate on
- `POST /api/projects/<id>/collaborators` — add a collaborator
- `POST /api/projects/<id>/uploads` — upload a version
  (`{content_base64, label?, filename?, content_type?}`); the server
  hashes the content, links it to its parent, and signs a ledger
  event. Re-uploading bytes identical to the latest version returns
  that version with `"duplicate": true` and adds no ledger event.
  Versions record filename, content type and byte size.
- `POST /api/projects/<id>/approvals` — approve a version
- `POST /api/projects/<id>/declarations` — declare AI use for a version
  (`{content_id, tool, prompt_summary?, sentence_indices?}`); the
  declaration is a signed ledger event, so it cannot be edited or
  dropped without breaking the chain
- `GET /api/projects/<id>/declarations` — list a project's declarations
- `GET /api/projects/<id>/contributions` — Human Contribution Map:
  every sentence with its source (human, AI-assisted, imported,
  external) plus coverage percentages
- `GET /api/projects/<id>/diff?from=&to=` — semantic sentence diff
  between two versions (defaults: latest version vs its parent)
- `GET /api/projects/<id>/versions?limit=&offset=` — version history
  with metadata, paged like events
- `GET /api/projects/<id>/versions/content?content_id=sha256:...`
- `GET /api/projects/<id>/events?limit=&offset=` — ledger events,
  newest first, paged (limit 1–200)
- `GET /api/projects/<id>/verify` — verification page data (hashes only)
- `GET /api/projects/<id>/export?claim=` — signed dispute evidence
  bundle, signed with the exporter's own key, carrying the versions,
  diffs, AI declarations, contribution coverage, actor public keys
  and export timestamp so a third party can re-verify it standalone
- `POST /api/bundles/verify` — verify a signed bundle, no auth: a
  third party checking a dispute needs no account

Auth design: an actor's Ed25519 signing key is derived from their
password (PBKDF2, separate salts for login check and key). The server
stores salts, a verifier and the public key — never a signing secret —
so a stolen data file cannot forge ledger events. State persists to a
JSON file; sessions live in memory only.
