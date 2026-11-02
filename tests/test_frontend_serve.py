"""The server serves the web UI itself: GET / is the page, and only
the whitelisted frontend assets are served under /static/."""

import http.client
import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.server import make_server


class TestFrontendServe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server, _ = make_server("127.0.0.1", 0,
                                    str(Path(cls.tmp.name) / "state.json"))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, resp.getheader("Content-Type"), resp.read()
        finally:
            conn.close()

    def test_root_serves_the_page(self):
        status, content_type, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn(b"<title>ProofTrail</title>", body)

    def test_static_assets_served(self):
        status, content_type, body = self.get("/static/app.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", content_type)
        self.assertIn(b"sessionStorage", body)
        status, content_type, body = self.get("/static/styles.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", content_type)

    def test_static_traversal_is_not_served(self):
        status, _, body = self.get("/static/../server.py")
        self.assertEqual(status, 404)
        self.assertNotIn(b"ProofTrailApp", body)
        status, _, _ = self.get("/static/secret.txt")
        self.assertEqual(status, 404)

    def test_api_still_works(self):
        status, content_type, body = self.get("/api/health")
        self.assertEqual(status, 200)
        self.assertIn(b'"ok"', body)


if __name__ == "__main__":
    unittest.main()
