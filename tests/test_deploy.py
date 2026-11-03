"""Deploy example checks: the Caddyfile must proxy to the localhost
app and must not disable TLS. This validates the example only — it
does not prove any deployment exists."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestDeployExample(unittest.TestCase):
    def test_caddyfile_proxies_to_localhost_app(self):
        text = (ROOT / "deploy" / "Caddyfile").read_text()
        self.assertIn("reverse_proxy 127.0.0.1:8000", text)

    def test_caddyfile_does_not_disable_tls(self):
        # Comments are prose, not config: only real directives count.
        lines = [line for line in
                 (ROOT / "deploy" / "Caddyfile").read_text().splitlines()
                 if not line.lstrip().startswith("#")]
        text = "\n".join(lines)
        self.assertNotIn("tls off", text)
        self.assertNotIn("http://", text)
        # A bare domain block is what makes Caddy enable HTTPS
        # automatically; the example must actually name one.
        self.assertRegex(text, r"(?m)^[a-z0-9.-]+\.[a-z]{2,} \{$")


if __name__ == "__main__":
    unittest.main()
