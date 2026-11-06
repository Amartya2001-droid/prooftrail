"""Project archiving: hidden from the default list, not locked,
and the flag survives a state reload."""

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.persistence import objects_from_state
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


class TestArchiveApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.state_path = str(Path(cls.tmp.name) / "state.json")
        cls.server, _ = make_server("127.0.0.1", 0, cls.state_path)
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

    def test_archive_hides_unarchive_restores(self):
        conn = self.conn()
        token = self._login(conn, "designer")
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Old deck"}, token=token)
        pid = proj["project_id"]
        status, archived = call(conn, "POST",
                                f"/api/projects/{pid}/archive", {},
                                token=token)
        self.assertEqual(status, 200)
        self.assertTrue(archived["archived"])
        _, page = call(conn, "GET", "/api/projects", token=token)
        self.assertEqual(page["projects"], [])
        self.assertEqual(page["total"], 0)
        _, page = call(conn, "GET",
                       "/api/projects?include_archived=true", token=token)
        self.assertEqual(page["total"], 1)
        self.assertTrue(page["projects"][0]["archived"])
        status, unarchived = call(conn, "POST",
                                  f"/api/projects/{pid}/unarchive", {},
                                  token=token)
        self.assertEqual(status, 200)
        self.assertFalse(unarchived["archived"])
        _, page = call(conn, "GET", "/api/projects", token=token)
        self.assertEqual(page["total"], 1)

    def test_archive_is_creator_only(self):
        conn = self.conn()
        token = self._login(conn, "owner")
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Deck"}, token=token)
        pid = proj["project_id"]
        other = self._login(conn, "reviewer")
        call(conn, "POST", f"/api/projects/{pid}/collaborators",
             {"username": "reviewer"}, token=token)
        status, body = call(conn, "POST", f"/api/projects/{pid}/archive",
                            {}, token=other)
        self.assertEqual(status, 403)
        self.assertIn("creator", body["error"])

    def test_archive_unknown_project_is_404(self):
        conn = self.conn()
        token = self._login(conn, "solo")
        status, _ = call(conn, "POST", "/api/projects/proj-nope/archive",
                         {}, token=token)
        self.assertEqual(status, 404)

    def test_archived_flag_survives_a_reload(self):
        conn = self.conn()
        token = self._login(conn, "keeper")
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Filed away"}, token=token)
        call(conn, "POST", f"/api/projects/{proj['project_id']}/archive",
             {}, token=token)
        with open(self.state_path) as handle:
            stored = json.load(handle)
        stored_project = stored["projects"][proj["project_id"]]
        self.assertTrue(stored_project["archived"])
        _, projects = objects_from_state(stored)
        self.assertTrue(projects[proj["project_id"]].archived)


if __name__ == "__main__":
    unittest.main()
