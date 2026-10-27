import base64
import copy
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


class TestBundleVerifyApi(unittest.TestCase):
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

    def test_verify_bundle_public_endpoint(self):
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
        call(conn, "POST", f"/api/projects/{pid}/uploads",
             {"content_base64": base64.b64encode(
                 b"We sell shoes.").decode(), "label": "v1"}, token=token)
        _, bundle = call(conn, "GET", f"/api/projects/{pid}/export",
                         token=token)

        # No token: a third party can verify without an account.
        status, result = call(conn, "POST", "/api/bundles/verify", bundle)
        self.assertEqual(status, 200)
        self.assertTrue(result["valid"])
        self.assertEqual(result["problems"], [])

        # Tampered content no longer matches its hash.
        tampered = copy.deepcopy(bundle)
        tampered["versions"][0]["content"] = "We sell hats."
        status, result = call(conn, "POST", "/api/bundles/verify", tampered)
        self.assertFalse(result["valid"])
        self.assertTrue(any("does not match its hash" in p
                            for p in result["problems"]))

        # Tampered signature fails the owner check.
        forged = copy.deepcopy(bundle)
        forged["owner_signature"] = "00" * 64
        status, result = call(conn, "POST", "/api/bundles/verify", forged)
        self.assertFalse(result["valid"])
        self.assertIn("owner signature invalid", result["problems"])

        # A non-object body is a 400, not a 500.
        status, _ = call(conn, "POST", "/api/bundles/verify", ["not", "a"])
        self.assertEqual(status, 400)
        conn.close()


if __name__ == "__main__":
    unittest.main()
