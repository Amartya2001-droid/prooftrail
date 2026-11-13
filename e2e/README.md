# Java browser end-to-end tests

Real Selenium 4 + JUnit 5 tests, built with Maven. The app remains Python; Java is
used to exercise its browser interface. No HTTP interception, mocked agent result,
LLM call, external API key or service credential is involved.

## Run

Requirements: Python 3.12, a JDK 17+ with a compiler (CI uses 21), Maven 3.9+, Chrome/Chromium and a
compatible driver. Selenium Manager can resolve the driver when network access
allows its downloads. An explicit matching driver avoids that download step.

From the repository root, in a first terminal:

```sh
# Start a disposable instance: these tests register accounts and write projects.
python3 -m prooftrail.server --host 127.0.0.1 --port 8000 --data /tmp/prooftrail-e2e.json
```

Use a fresh data path for each complete run. The app limits registrations per IP;
repeated runs against one long-lived process can hit that limit. Do not point this
suite at production or a dataset you need to keep. There is no account/project
purge API, and the tests deliberately do not bypass the app to delete records.
Stop the disposable server and remove its data and backup files when finished.

In a second terminal:

```sh
mvn --batch-mode --no-transfer-progress -f e2e/pom.xml verify
```

All browser tests run headlessly and independently, without fixed test sleeps or
an ordering requirement. The agent operations verify real Ed25519 signatures in
pure Python, so waits allow up to 120 seconds for UI results. The separate demo
process has a 180-second deadline. The activity test waits up to 35 seconds for
the existing 10-second HTTP polling interval.

| Environment variable | Default / purpose |
| --- | --- |
| `APP_BASE_URL` | `http://127.0.0.1:8000`; an HTTP(S) origin, without credentials/path/query |
| `CHROME_BINARY` | Optional explicit Chrome/Chromium executable |
| `CHROMEDRIVER_PATH` | Optional compatible ChromeDriver executable; otherwise Selenium Manager |
| `CHROME_NO_SANDBOX` | `false`; use `true` only where a container requires it |
| `PYTHON_EXECUTABLE` | `python3`; runs the local demo and reads its text fixtures |

Example with a nondefault local port and an installed driver:

```sh
APP_BASE_URL=http://127.0.0.1:8765 \
CHROME_BINARY=/usr/bin/chromium CHROMEDRIVER_PATH=/path/to/chromedriver \
mvn -f e2e/pom.xml verify
```

The base URL changes the browser target. The demo CLI always runs from this
checkout; it does not connect to that URL or establish remote deployment health.
For a sandbox with a read-only home, add `-Dmaven.repo.local=/writable/path/m2`.
No credentials are read from the environment: each browser test registers unique,
disposable accounts at runtime and keeps the generated passwords in memory.

## Five checks

- Landing page and signed-in Projects dashboard, empty list, and Agent team
  guidance when no project is selected.
- Project creation, pasted-text upload, hash-only verification, and project list.
- The demo's actual `V1`/`V2`/`V3` text loaded from Python: two collaborators,
  declared AI-assisted v2, undeclared v3 rewrite, both agent tasks, real findings,
  persisted run history, activity events, and ledger verification afterward.
- Activity polling across two real browser tabs: a second upload appears without
  clicking refresh; manual refresh and newest-first ordering are also checked.
- Existing `demo/agent_team_scenario.py` CLI completes both tasks and reports two
  runs, valid ledger, rewrite findings and the honest limitations.

The declaration is synthetic test input, not evidence of an actual AI-generated
passage. Scribe's narration is deterministic template text. A clean verdict means
no high-severity findings; medium/low rewrite and undeclared-use findings remain.
These tests do not prove real-world authorship, production TLS, or Supabase access.

## CI and failure evidence

`.github/workflows/ci.yml` runs this as a separate Java Selenium E2E job for PRs
and pushes to main. It starts a fresh Python app on port 8000, waits for health,
installs matching Chrome/ChromeDriver, runs Maven, uploads JUnit reports and
failure screenshots, and stops the app even after failure. No persistent state,
passwords or session tokens are uploaded. Reports are in
`e2e/target/surefire-reports/`; screenshots are in `e2e/target/screenshots/`.
