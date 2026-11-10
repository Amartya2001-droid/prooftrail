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

The agent-team scenario builds a disputed announcement and runs
both agent tasks on it:

```sh
python3 demo/agent_team_scenario.py
```

## Web UI

The server serves a small web UI itself, no build step. Start it
and open http://127.0.0.1:8000 in a browser:

```sh
python3 -m prooftrail.server --port 8000
```

The UI covers account sign-in (including second factor), projects,
versions and approvals, the verification view (hashes only, never
document content), the diff viewer, AI-use declarations with the
contribution map, and evidence-bundle export with sessions and the
authentication audit. The session token is kept in sessionStorage
only, so closing the tab signs the browser out.

## Agent team

Five named specialists work a project when you run the team, from
the Agent team tab or from `POST /api/projects/<id>/agents/run`
with `{"kind": "verify_project"}` or
`{"kind": "build_dispute_case"}`:

- **Trailboss** (orchestrator) — picks the team for the task and
  merges their findings into one report.
- **Verity** (verifier) — re-verifies hash chains, signatures and
  timestamps, one finding per version plus one for the chain.
- **Sleuth** (detective) — hunts sudden rewrites, authorship flips,
  undeclared AI use and timeline gaps, from sentence diffs and the
  declarations on record.
- **Mapper** (cartographer) — maps who wrote what, per version and
  per actor: human vs AI-assisted vs imported segments.
- **Scribe** (narrator) — turns the team's evidence into a
  plain-language proof narrative.

Every run writes signed events into the project's ledger as it
happens (started, one per finding, finished), so a run's findings
are tamper-evident like everything else, and the run is recorded
in the run log. The Agent team tab also shows a live activity
feed: the newest ledger events and agent runs merged into one
timeline, polling every 10 seconds while the tab is open — the
server speaks plain HTTP and has no push channel.

Honest limits, stated where they matter: the verdict is "clean"
unless a finding is high severity, so a flagged rewrite alone
does not escalate it. Sleuth's undeclared-addition finding is not
proof of AI use — it only means no AI use was declared. Scribe's
narrative is deterministic template text built from the team's
findings, not LLM reasoning. Imported and external shares in the
contribution map are 0% because the project stores no explicit
tagging for them yet — a gap in the record, not proof none exist.
And the app is still localhost-only with no TLS of its own; see
Deploying below.

## Deploying (not deployed yet)

Live status: **not live yet** — blocked by production host/domain and DNS,
TLS proxy setup, and production Supabase environment provisioning. There is no
live URL. See [DEPLOY.md](DEPLOY.md) for the deployment preparation runbook.

The server binds to 127.0.0.1 by default and has no TLS of its own,
so a public deployment is a reverse proxy in front of it, never the
app exposed directly. `deploy/Caddyfile` is a working example: Caddy
terminates TLS for your domain automatically and proxies to the app
on localhost. Until that proxy is in place, this is a localhost app,
not a production service — the CI badge above proves the tests pass,
not that anything is served publicly.

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
- `GET /api/sessions` — list my sessions, with the current one flagged
- `POST /api/sessions/revoke-one` — revoke one session by id
- `GET /api/sessions/audit` — my authentication audit trail
- `POST /api/users/password` — change password, other sessions revoked
- `POST /api/users/totp/setup` — start optional TOTP enrollment
- `POST /api/users/totp/confirm` — confirm TOTP enrollment
- `POST /api/users/totp/disable` — disable TOTP (password required)
- `POST /api/users/totp/recovery` — regenerate the recovery codes
  (password required; the old codes stop working at once)
- `POST /api/sessions/totp` — complete a pending TOTP login
- `GET /api/openapi.json` — machine-readable API spec
- `POST /api/projects` — create a project
- `POST /api/projects/<id>/rename` — rename a project (creator only)
- `GET /api/projects` — list the projects you collaborate on, newest first
  (paged; `q` filters titles by case-insensitive substring;
  `include_archived=true` also lists archived projects, which are
  hidden by default)
- `POST /api/projects/<id>/archive` — archive a project (creator
  only; hides it from the default list, does not lock it)
- `POST /api/projects/<id>/unarchive` — unarchive a project
  (creator only)
- `POST /api/projects/<id>/collaborators` — add a collaborator
- `POST /api/projects/<id>/collaborators/remove` — remove a collaborator (creator only)
- `POST /api/projects/<id>/uploads` — upload a version
  (`{content_base64, label?, filename?, content_type?}`); the server
  hashes the content, links it to its parent, and signs a ledger
  event. Re-uploading bytes identical to the latest version returns
  that version with `"duplicate": true` and adds no ledger event.
  Versions record filename, content type and byte size.
- `POST /api/projects/<id>/restore` — re-publish an older version as
  the newest (`{content_id}`): its bytes become a new version with
  the current latest as parent, labelled "Restored from …", with a
  `restore` ledger event. Restoring the latest version is rejected.
- `POST /api/projects/<id>/approvals` — approve a version (optional
  `comment`, at most 500 characters, recorded in the signed approval
  event; a repeat approval by the same actor is idempotent and keeps
  the first comment)
- `GET /api/projects/<id>/approvals` — list approvals with comments,
  paged (`limit`/`offset`)
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
  bundle (claim at most 500 characters), signed with the exporter's own key, carrying the versions,
  diffs, AI declarations, contribution coverage, actor public keys
  and export timestamp so a third party can re-verify it standalone
- `POST /api/bundles/verify` — verify a signed bundle, no auth: a
  third party checking a dispute needs no account

Auth design: an actor's Ed25519 signing key is derived from their
password (PBKDF2, separate salts for login check and key). The server
stores salts, a verifier and the public key — never a signing secret —
so a stolen data file cannot forge ledger events. State persists to a
JSON file; sessions live in memory only.
