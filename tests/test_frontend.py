"""Frontend wiring checks: the JavaScript must only refer to elements
that actually exist in index.html, so a renamed button cannot silently
stop working. The server-serving checks live in test_frontend_serve.py
once the server gains its static route."""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"


def html_ids():
    text = (FRONTEND / "index.html").read_text()
    return set(re.findall(r'id="([^"]+)"', text))


def js_ids():
    text = (FRONTEND / "app.js").read_text()
    ids = set(re.findall(r'\$\("([^"]+)"\)', text))
    sections = re.search(r"const SECTIONS = \[(.*?)\];", text, re.S)
    if sections:
        for name in re.findall(r'"([^"]+)"', sections.group(1)):
            ids.add("section-" + name)
            ids.add("nav-" + name)
    return ids


class TestFrontendWiring(unittest.TestCase):
    def test_js_is_valid(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node not installed")
        result = subprocess.run(
            [node, "--check", str(FRONTEND / "app.js")],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_js_element_exists_in_html(self):
        missing = sorted(js_ids() - html_ids())
        self.assertEqual(missing, [])

    def test_no_function_is_declared_twice(self):
        # A duplicated top-level function declaration silently wins by
        # position, so a later edit to the first copy changes nothing.
        # That is how a stale refreshAuthState survived unnoticed.
        text = (FRONTEND / "app.js").read_text()
        names = re.findall(r"^function (\w+)\(", text, re.M)
        duplicates = sorted({name for name in names
                             if names.count(name) > 1})
        self.assertEqual(duplicates, [])

    def test_html_loads_the_js_and_css(self):
        text = (FRONTEND / "index.html").read_text()
        self.assertIn('src="/static/app.js"', text)
        self.assertIn('href="/static/styles.css"', text)

    def test_versions_list_has_a_download_button(self):
        # The versions list must offer a download: the content
        # endpoint exists, but without a button the UI cannot reach it.
        text = (FRONTEND / "app.js").read_text()
        self.assertIn("versions/content", text)
        self.assertIn('"Download"', text)
        self.assertIn("anchor.download", text)

    def test_sessions_show_expiry_and_audit_uses_event_field(self):
        # The sessions API already returns created/last_seen/
        # expires_at; the UI must show them, or a stale session looks
        # live. And audit events carry their kind in "event": reading
        # "type" rendered every audit row as "undefined".
        text = (FRONTEND / "app.js").read_text()
        self.assertIn("expires_at", text)
        self.assertIn("created_at", text)
        self.assertIn("remote_addr", text)
        self.assertNotIn("ip_address", text)
        self.assertIn('event.event + " — " + event.timestamp', text)

    def test_versions_tab_has_a_paste_text_upload(self):
        # A quick text version must not need a file: the Versions tab
        # offers a paste box that uploads as text/plain.
        text = (FRONTEND / "app.js").read_text()
        self.assertIn("form-upload-text", text)
        self.assertIn("upload-text", text)
        self.assertIn("text/plain", text)

    def test_projects_tab_has_archive_controls(self):
        # Archiving is a list concern, so the Projects tab needs the
        # toggle and the per-project Archive/Unarchive button.
        text = (FRONTEND / "app.js").read_text()
        self.assertIn("project-show-archived", text)
        self.assertIn("include_archived", text)
        self.assertIn('"Archive"', text)
        self.assertIn('"Unarchive"', text)

    def test_agent_team_tab_runs_the_team_and_shows_the_report(self):
        # The Agent team tab must offer both run kinds, call the run
        # endpoint, and render the returned verdict, summaries and
        # findings — otherwise the team can only run from code.
        js = (FRONTEND / "app.js").read_text()
        html = (FRONTEND / "index.html").read_text()
        self.assertIn('"agents"', js)
        self.assertIn("button-run-verify", js)
        self.assertIn("button-run-dispute", js)
        self.assertIn("/agents/run", js)
        self.assertIn('"verify_project"', js)
        self.assertIn('"build_dispute_case"', js)
        self.assertIn("agent-report-verdict", js)
        self.assertIn("agent-report-summaries", js)
        self.assertIn("agent-report-findings", js)
        self.assertIn("agent-runs-list", js)
        self.assertIn("Trailboss", html)
        self.assertIn("Verity", html)
        self.assertIn("Sleuth", html)
        self.assertIn("Mapper", html)
        self.assertIn("Scribe", html)


if __name__ == "__main__":
    unittest.main()
