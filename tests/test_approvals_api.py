"""Approval comments: the reason for an approval is part of the
signed history, and the approvals list shows who approved what."""

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


class TestApprovalComments(unittest.TestCase):
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

    def _project_with_version(self, conn, token):
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Brand deck"}, token=token)
        pid = proj["project_id"]
        _, up = call(conn, "POST", f"/api/projects/{pid}/uploads",
                     {"content_base64": base64.b64encode(
                         b"First draft.").decode(), "label": "v1"},
                     token=token)
        return pid, up["content_id"]

    def test_comment_is_recorded_and_listed(self):
        conn = self.conn()
        call(conn, "POST", "/api/users",
             {"username": "designer", "name": "Designer",
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "designer", "password": "sunset-river-42"})
        token = login["token"]
        pid, cid = self._project_with_version(conn, token)

        status, _ = call(conn, "POST", f"/api/projects/{pid}/approvals",
                         {"content_id": cid,
                          "comment": "Client signed off on v1."},
                         token=token)
        self.assertEqual(status, 200)
        status, listed = call(conn, "GET",
                              f"/api/projects/{pid}/approvals", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["approvals"][0]["actor_id"], "designer")
        self.assertEqual(listed["approvals"][0]["content_id"], cid)
        self.assertEqual(listed["approvals"][0]["comment"],
                         "Client signed off on v1.")

    def test_comment_too_long_is_rejected(self):
        conn = self.conn()
        call(conn, "POST", "/api/users",
             {"username": "writer", "name": "Writer",
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "writer", "password": "sunset-river-42"})
        token = login["token"]
        pid, cid = self._project_with_version(conn, token)

        status, body = call(conn, "POST", f"/api/projects/{pid}/approvals",
                            {"content_id": cid, "comment": "x" * 501},
                            token=token)
        self.assertEqual(status, 400)
        self.assertIn("comment", body["error"])

    def test_repeat_approval_keeps_the_first_comment(self):
        # The ledger is append-only, so a second approval by the same
        # actor returns the original event instead of a new one: the
        # comment rides on the first approval only.
        conn = self.conn()
        call(conn, "POST", "/api/users",
             {"username": "editor", "name": "Editor",
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "editor", "password": "sunset-river-42"})
        token = login["token"]
        pid, cid = self._project_with_version(conn, token)

        call(conn, "POST", f"/api/projects/{pid}/approvals",
             {"content_id": cid, "comment": "First look, approved."},
             token=token)
        call(conn, "POST", f"/api/projects/{pid}/approvals",
             {"content_id": cid, "comment": "Changed my mind."},
             token=token)
        _, listed = call(conn, "GET",
                         f"/api/projects/{pid}/approvals", token=token)
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["approvals"][0]["comment"],
                         "First look, approved.")

    def test_approvals_are_collaborator_only(self):
        conn = self.conn()
        call(conn, "POST", "/api/users",
             {"username": "owner", "name": "Owner",
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "owner", "password": "sunset-river-42"})
        token = login["token"]
        pid, cid = self._project_with_version(conn, token)
        call(conn, "POST", f"/api/projects/{pid}/approvals",
             {"content_id": cid}, token=token)

        call(conn, "POST", "/api/users",
             {"username": "outsider", "name": "Outsider",
              "password": "sunset-river-42"})
        _, other = call(conn, "POST", "/api/sessions",
                        {"username": "outsider",
                         "password": "sunset-river-42"})
        status, _ = call(conn, "GET", f"/api/projects/{pid}/approvals",
                         token=other["token"])
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
