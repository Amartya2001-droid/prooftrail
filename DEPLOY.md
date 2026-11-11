# Production deployment preparation

Status: **not live yet**. ProofTrail is currently localhost-only; no production
URL, domain, host or deployed Supabase connection has been verified. Days 1 and 2
only prepare and verify this runbook; they do not deploy anything. `example.com`
in the existing Caddyfile is a placeholder, not the live URL.

## Runtime and topology

Use Python 3.12 (the CI version). The application uses the Python standard
library and serves the frontend itself; there is no frontend build or package
installation step. Run from the repository root so the package is importable.

Public HTTPS on port 443 -> Caddy TLS reverse proxy -> ProofTrail on
**127.0.0.1:8000**. The app provides no TLS. Keep port 8000 private and retain
`--host 127.0.0.1`. The port is selected by `--port` (default 8000), not a `PORT`
environment variable. If changing it, change the proxy upstream too.

Before a later deployment, Amartya must supply a production host, domain and DNS
pointing to that host. Allow inbound TCP 80 and 443 for Caddy's automatic HTTPS
and redirects/certificate validation; do not expose 8000. Allow outbound HTTPS
to the chosen Supabase project and the certificate authority. Caddy and the app
must share the host/network namespace for the existing loopback upstream to work.
Separate containers require a separately reviewed private-network configuration.

Use `deploy/Caddyfile`, replace `example.com` with the chosen domain, validate it
with `caddy validate --config deploy/Caddyfile --adapter caddyfile`, and run Caddy
with that explicit config path. Keep Caddy's certificate storage persistent.

## Supabase prerequisites and environment

The production app process needs these variables, provided by the host's secret
manager or a restricted environment file outside the repository:

| Variable | Required value |
| --- | --- |
| `PROOFTRAIL_STATE_BACKEND` | `supabase` (otherwise JSON remains the default) |
| `SUPABASE_URL` | Actual project HTTPS base URL |
| `SUPABASE_SERVICE_KEY` | Server-side service key authorized to read/upsert the table |

`SUPABASE_KEY` is a legacy fallback; `SUPABASE_SERVICE_KEY` takes precedence.
Use the explicit service-key name. Never put keys in the frontend, Caddyfile,
command history, tracked files or logs. No secret values are included here.
The Day 2 verification environment has none of these variables configured;
no live Supabase request was made.

Provision the table in the intended Supabase database before starting the app:

```sql
CREATE TABLE IF NOT EXISTS public.prooftrail_state (
    id text PRIMARY KEY,
    state jsonb
);
ALTER TABLE public.prooftrail_state ENABLE ROW LEVEL SECURITY;
```

Keep the table inaccessible to anonymous/client roles; use only the server-side
service role. Verify the project exposes it through PostgREST and that the
service key permits GET and POST upserts on `/rest/v1/prooftrail_state`.
The app stores all state in a single row, `id = 'main'`, loaded at startup and
upserted on each mutation. The backend does not create tables. Invalid stored
state or exhausted network retries fails loudly. Supabase unit tests use fakes;
they do not establish production connectivity.

## Process and data preparation for a later deployment

After the environment is injected, the app command is:

```sh
python3 -m prooftrail.server --host 127.0.0.1 --port 8000 --data /var/lib/prooftrail/prooftrail-data.json
```

The path above is an example host path to provision for a dedicated unprivileged
service account. The default CLI path is `prooftrail-data.json`. The file is
loaded even when Supabase is selected: an existing Supabase row takes precedence;
if no row exists, file-loaded state seeds memory and migrates on the first save.
Decide explicitly whether to migrate existing local data or start empty. Back up
and validate the intended source first; do not accidentally seed production from
a developer data file. Without Supabase, the JSON path must be on durable storage.

Run **one app process/replica**. State, sessions and throttles are in memory;
Supabase holds a single snapshot, not shared concurrent application state.
Multiple writers can overwrite each other's snapshots. A restart invalidates
sessions. Configure a service supervisor with a fixed working directory,
restricted credentials, restart policy and logs. Arrange database backups and a
restore procedure before accepting real data; Supabase has no local `.bak`
fallback. Health checks alone do not verify persistence.

## Agent team runtime and release verification

The existing Agent team tab runs the team through authenticated
`POST /api/projects/<id>/agents/run`, with JSON
`{"kind": "verify_project"}` or `{"kind": "build_dispute_case"}`. Use a project
accessible to the signed-in account. Runs execute synchronously and write signed
ledger events and a persisted run log, so invoking this endpoint changes state.
Include these writes in the persistence/restart checks below using test data.

The tab merges the project's newest ledger events and agent runs into an activity
feed and polls every 10 seconds while open. It uses ordinary HTTP requests, not
WebSockets or server-sent events; no push-channel proxy configuration is needed.
Run history is available at `GET /api/projects/<id>/agents/runs` and
`GET /api/agents/runs` (both authenticated).

For a later release, check both task kinds from the tab, the refreshed feed and
run history, and persistence after restart. The unchanged local scenario can also
be run with `python3 demo/agent_team_scenario.py`; it exercises both task kinds in
memory, not the HTTP proxy or production Supabase connection.

## Later release checks (no deployment performed on Days 1 or 2)

1. Run `python3 -m unittest discover -s tests -v` and verify the selected commit's
   GitHub CI succeeds before release.
2. Confirm environment injection without printing values; verify table access and
   startup load in the intended project. Resolve any load errors before serving.
3. Verify local `http://127.0.0.1:8000/api/health`, then public
   `https://<chosen-domain>/api/health`, frontend loading, valid TLS and HTTP-to-HTTPS
   redirection. Confirm port 8000 is unreachable externally.
4. With an authorized test account, check a write/read and persistence across an
   app restart. Review logs without exposing tokens, keys or document contents.
5. Record the actual HTTPS URL and verified behavior in README and the daily log.
   Keep the previous release and database backup available for rollback; do not
   roll back state blindly after new writes.

Outstanding decisions for Amartya: production host/domain and DNS, secure Supabase
URL/service-key provisioning, database/table readiness, data migration choice,
backup ownership and operational process supervision. No agent-team code changes
are needed or included in this preparation.
