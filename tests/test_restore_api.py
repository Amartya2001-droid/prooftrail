"""Restore: an older version re-published as the newest one, with
the rollback visible in the ledger instead of rewriting history."""

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


class TestRestoreApi(unittest.TestCase):
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

    def _setup(self, conn):
        call(conn, "POST", "/api/users",
             {"username": "designer", "name": "Designer",
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "designer", "password": "sunset-river-42"})
        token = login["token"]
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Brand deck"}, token=token)
        pid = proj["project_id"]
        ids = []
        for i, text in enumerate((b"First draft.", b"Second draft.",
                                  b"Third draft.")):
            _, up = call(conn, "POST", f"/api/projects/{pid}/uploads",
                         {"content_base64": base64.b64encode(text).decode(),
                          "label": f"v{i + 1}"}, token=token)
            ids.append(up["content_id"])
        return token, pid, ids

    def test_restore_older_version_becomes_newest(self):
        conn = self.conn()
        token, pid, ids = self._setup(conn)
        status, restored = call(conn, "POST",
                                f"/api/projects/{pid}/restore",
                                {"content_id": ids[0]}, token=token)
        self.assertEqual(status, 201)
        self.assertEqual(restored["restored_from"], ids[0])
        self.assertTrue(restored["label"].startswith("Restored from"))
        self.assertEqual(restored["parent_content_id"], ids[2])
        # The restored bytes are the old version's bytes.
        _, content = call(conn, "GET",
                          f"/api/projects/{pid}/versions/content"
                          f"?content_id={restored['content_id']}",
                          token=token)
        self.assertEqual(base64.b64decode(content["content_base64"]),
                         b"First draft.")
        # The rollback is a ledger event, and the chain still verifies.
        _, events = call(conn, "GET", f"/api/projects/{pid}/events",
                         token=token)
        self.assertEqual(events["events"][0]["type"], "restore")
        _, page = call(conn, "GET", f"/api/projects/{pid}/verify",
                       token=token)
        self.assertTrue(page["ledger_valid"], page["ledger_problems"])

    def test_restore_latest_is_rejected(self):
        conn = self.conn()
        token, pid, ids = self._setup(conn)
        status, body = call(conn, "POST", f"/api/projects/{pid}/restore",
                            {"content_id": ids[2]}, token=token)
        self.assertEqual(status, 400)
        self.assertIn("latest", body["error"])

    def test_restore_unknown_version_is_404(self):
        conn = self.conn()
        token, pid, _ = self._setup(conn)
        status, _ = call(conn, "POST", f"/api/projects/{pid}/restore",
                         {"content_id": "0" * 64}, token=token)
        self.assertEqual(status, 404)

    def test_restore_is_collaborator_only(self):
        conn = self.conn()
        token, pid, ids = self._setup(conn)
        call(conn, "POST", "/api/users",
             {"username": "outsider", "name": "Outsider",
              "password": "sunset-river-42"})
        _, other = call(conn, "POST", "/api/sessions",
                        {"username": "outsider",
                         "password": "sunset-river-42"})
        status, _ = call(conn, "POST", f"/api/projects/{pid}/restore",
                         {"content_id": ids[0]}, token=other["token"])
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
