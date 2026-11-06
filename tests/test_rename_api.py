"""Project rename: creator-only, like inviting collaborators."""

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


class TestRenameApi(unittest.TestCase):
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

    def _login(self, conn, username):
        call(conn, "POST", "/api/users",
             {"username": username, "name": username.title(),
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": username, "password": "sunset-river-42"})
        return login["token"]

    def test_rename_updates_the_listed_title(self):
        conn = self.conn()
        token = self._login(conn, "designer")
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Brand deck"}, token=token)
        pid = proj["project_id"]
        status, renamed = call(conn, "POST",
                               f"/api/projects/{pid}/rename",
                               {"title": "Brand deck, final"}, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(renamed["title"], "Brand deck, final")
        _, page = call(conn, "GET", "/api/projects", token=token)
        self.assertEqual(page["projects"][0]["title"], "Brand deck, final")

    def test_rename_rejects_empty_and_long_titles(self):
        conn = self.conn()
        token = self._login(conn, "writer")
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Draft"}, token=token)
        pid = proj["project_id"]
        status, body = call(conn, "POST", f"/api/projects/{pid}/rename",
                            {"title": "   "}, token=token)
        self.assertEqual(status, 400)
        self.assertIn("title", body["error"])
        status, _ = call(conn, "POST", f"/api/projects/{pid}/rename",
                         {"title": "x" * 201}, token=token)
        self.assertEqual(status, 400)

    def test_rename_is_creator_only(self):
        conn = self.conn()
        token = self._login(conn, "owner")
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Deck"}, token=token)
        pid = proj["project_id"]
        other = self._login(conn, "reviewer")
        call(conn, "POST", f"/api/projects/{pid}/collaborators",
             {"username": "reviewer"}, token=token)
        status, body = call(conn, "POST", f"/api/projects/{pid}/rename",
                            {"title": "Renamed by reviewer"}, token=other)
        self.assertEqual(status, 403)
        self.assertIn("creator", body["error"])

    def test_rename_unknown_project_is_404(self):
        conn = self.conn()
        token = self._login(conn, "solo")
        status, _ = call(conn, "POST", "/api/projects/proj-nope/rename",
                         {"title": "New"}, token=token)
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
