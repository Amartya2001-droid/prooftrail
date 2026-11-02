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

    def test_html_loads_the_js_and_css(self):
        text = (FRONTEND / "index.html").read_text()
        self.assertIn('src="/static/app.js"', text)
        self.assertIn('href="/static/styles.css"', text)


if __name__ == "__main__":
    unittest.main()
