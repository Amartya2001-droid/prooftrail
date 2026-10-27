import base64
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.server import make_server


def call(conn, method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request(method, path, json.dumps(body) if body is not None else None,
                 headers)
    resp = conn.getresponse()
    data = json.loads(resp.read() or b"{}")
    return resp.status, data


class TestDiffApi(unittest.TestCase):
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

    def conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)

    def test_diff_explicit_and_default(self):
        conn = self.conn()
        call(conn, "POST", "/api/users",
             {"username": "designer", "name": "Designer",
              "password": "password123"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "designer", "password": "password123"})
        token = login["token"]
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Brand Deck"}, token=token)
        pid = proj["project_id"]

        def upload(text, label):
            return call(conn, "POST", f"/api/projects/{pid}/uploads",
                        {"content_base64": base64.b64encode(
                            text.encode()).decode(), "label": label},
                        token=token)

        _, v1 = upload("We sell shoes. Prices are low.", "v1")
        _, v2 = upload("We sell shoes. Delivery is free.", "v2")

        status, diff = call(
            conn, "GET",
            f"/api/projects/{pid}/diff?from={v1['content_id']}"
            f"&to={v2['content_id']}", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(diff["from_label"], "v1")
        self.assertEqual(diff["to_label"], "v2")
        self.assertEqual(diff["added"], ["Delivery is free."])
        self.assertEqual(diff["removed"], ["Prices are low."])
        self.assertEqual(diff["unchanged"], ["We sell shoes."])
        # 1 of 2 sentences replaced on each side: 50% churn both ways.
        self.assertEqual(diff["intent"], "rewrite")
        self.assertIn("sentence(s) added", diff["summary"])

        # No query params: latest version against its parent, same diff.
        status, default = call(conn, "GET", f"/api/projects/{pid}/diff",
                               token=token)
        self.assertEqual(status, 200)
        self.assertEqual(default["added"], diff["added"])
        self.assertEqual(default["removed"], diff["removed"])

        # Diffing a version against itself: nothing changed.
        status, same = call(
            conn, "GET",
            f"/api/projects/{pid}/diff?from={v1['content_id']}"
            f"&to={v1['content_id']}", token=token)
        self.assertEqual(same["added"], [])
        self.assertEqual(same["intent"], "touch-up")

        # Unknown version -> 404; unauthenticated -> 401.
        status, _ = call(conn, "GET",
                         f"/api/projects/{pid}/diff?from={'0' * 64}"
                         f"&to={v2['content_id']}", token=token)
        self.assertEqual(status, 404)
        status, _ = call(conn, "GET", f"/api/projects/{pid}/diff")
        self.assertEqual(status, 401)
        conn.close()


if __name__ == "__main__":
    unittest.main()
