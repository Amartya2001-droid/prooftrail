"""Week-1 improvement tests, each against its own project and state."""

import base64
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.server import make_server


def call(conn, method, path, body=None, token=None, headers=None):
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    conn.request(method, path, json.dumps(body) if body is not None else None,
                 hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    try:
        data = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        data = {}
    return resp.status, data


class ImprovementTestCase(unittest.TestCase):
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

    def setUp(self):
        self.conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                               timeout=30)
        self._n = getattr(self, "_n", 0) + 1
        ImprovementTestCase._n = self._n

    def tearDown(self):
        self.conn.close()

    def user(self, name):
        status, _ = call(self.conn, "POST", "/api/users",
                         {"username": name, "name": name,
                          "password": "password123"})
        self.assertIn(status, (201, 409))
        status, login = call(self.conn, "POST", "/api/sessions",
                             {"username": name, "password": "password123"})
        self.assertEqual(status, 200)
        return login["token"]

    def project(self, token, title="Project"):
        status, proj = call(self.conn, "POST", "/api/projects",
                            {"title": title}, token=token)
        self.assertEqual(status, 201)
        return proj["project_id"]

    def upload(self, token, pid, text, label="v1", **extra):
        body = {"content_base64": base64.b64encode(text.encode()).decode(),
                "label": label}
        body.update(extra)
        status, version = call(self.conn, "POST",
                               f"/api/projects/{pid}/uploads",
                               body, token=token)
        self.assertEqual(status, 201)
        return version


class TestListProjects(ImprovementTestCase):
    def test_lists_only_own_projects(self):
        alice = self.user("alice-list")
        bob = self.user("bob-list")
        pid_a = self.project(alice, "Alice Project")
        self.project(bob, "Bob Project")
        status, body = call(self.conn, "GET", "/api/projects", token=alice)
        self.assertEqual(status, 200)
        ids = [p["project_id"] for p in body["projects"]]
        self.assertIn(pid_a, ids)
        self.assertEqual(len(ids), 1)
        self.assertEqual(body["projects"][0]["versions"], 0)


class TestVersionMetadata(ImprovementTestCase):
    def test_filename_type_and_size_round_trip(self):
        alice = self.user("alice-meta")
        pid = self.project(alice, "Meta Project")
        text = "hello metadata"
        version = self.upload(alice, pid, text, label="draft",
                              filename="brief.txt", content_type="text/plain")
        self.assertEqual(version["filename"], "brief.txt")
        self.assertEqual(version["content_type"], "text/plain")
        self.assertEqual(version["size"], len(text))
        status, body = call(self.conn, "GET",
                            f"/api/projects/{pid}/versions", token=alice)
        self.assertEqual(status, 200)
        self.assertEqual(body["versions"][0]["filename"], "brief.txt")
        self.assertEqual(body["versions"][0]["size"], len(text))


if __name__ == "__main__":
    unittest.main()
