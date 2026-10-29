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


class TestPagingApi(unittest.TestCase):
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

    def test_versions_and_projects_paging(self):
        conn = self.conn()
        call(conn, "POST", "/api/users",
             {"username": "designer", "name": "Designer",
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "designer", "password": "sunset-river-42"})
        token = login["token"]

        pids = []
        for title in ("Alpha", "Beta", "Gamma"):
            _, proj = call(conn, "POST", "/api/projects",
                           {"title": title}, token=token)
            pids.append(proj["project_id"])
        pid = pids[0]
        for i in range(5):
            call(conn, "POST", f"/api/projects/{pid}/uploads",
                 {"content_base64": base64.b64encode(
                     f"draft {i}.".encode()).decode(), "label": f"v{i + 1}"},
                 token=token)

        # Second page of versions: labels v2, v3 of 5 total.
        status, page = call(conn, "GET",
                            f"/api/projects/{pid}/versions?limit=2&offset=1",
                            token=token)
        self.assertEqual(status, 200)
        self.assertEqual([v["label"] for v in page["versions"]],
                         ["v2", "v3"])
        self.assertEqual(page["total"], 5)
        self.assertEqual((page["limit"], page["offset"]), (2, 1))

        # Past the end: empty page, total still honest.
        status, page = call(conn, "GET",
                            f"/api/projects/{pid}/versions?limit=2&offset=5",
                            token=token)
        self.assertEqual(page["versions"], [])
        self.assertEqual(page["total"], 5)

        # Project list paging: 2 of 3 on the first page.
        status, listing = call(conn, "GET", "/api/projects?limit=2",
                               token=token)
        self.assertEqual(len(listing["projects"]), 2)
        self.assertEqual(listing["total"], 3)

        # Bad paging is a 400 on every paged route.
        for path in (f"/api/projects/{pid}/versions?limit=0",
                     f"/api/projects/{pid}/versions?offset=-1",
                     "/api/projects/{pid}/versions?limit=abc",
                     "/api/projects/{pid}/events?limit=201",
                     "/api/projects?limit=0"):
            status, _ = call(conn, "GET", path, token=token)
            self.assertEqual(status, 400, path)
        conn.close()


if __name__ == "__main__":
    unittest.main()
