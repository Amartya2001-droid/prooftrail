"""Project search: GET /api/projects?q= filters titles by
case-insensitive substring, paged like the unfiltered list."""

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


class TestProjectSearch(unittest.TestCase):
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

    def test_search_filters_titles_case_insensitively(self):
        conn = self.conn()
        call(conn, "POST", "/api/users",
             {"username": "designer", "name": "Designer",
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "designer", "password": "sunset-river-42"})
        token = login["token"]
        for title in ("Brand deck", "brand guidelines", "Invoice dispute"):
            call(conn, "POST", "/api/projects", {"title": title},
                 token=token)

        status, page = call(conn, "GET", "/api/projects?q=BRAND",
                            token=token)
        self.assertEqual(status, 200)
        self.assertEqual(page["total"], 2)
        self.assertEqual(sorted(p["title"] for p in page["projects"]),
                         ["Brand deck", "brand guidelines"])

        # No match: empty page, honest total.
        _, page = call(conn, "GET", "/api/projects?q=zzz", token=token)
        self.assertEqual(page["projects"], [])
        self.assertEqual(page["total"], 0)

        # No query: the full list, newest first.
        _, page = call(conn, "GET", "/api/projects", token=token)
        self.assertEqual(page["total"], 3)
        self.assertEqual(page["projects"][0]["title"], "Invoice dispute")

    def test_search_only_sees_my_projects(self):
        conn = self.conn()
        call(conn, "POST", "/api/users",
             {"username": "owner", "name": "Owner",
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": "owner", "password": "sunset-river-42"})
        call(conn, "POST", "/api/projects", {"title": "Secret brand"},
             token=login["token"])
        call(conn, "POST", "/api/users",
             {"username": "other", "name": "Other",
              "password": "sunset-river-42"})
        _, other = call(conn, "POST", "/api/sessions",
                        {"username": "other", "password": "sunset-river-42"})
        _, page = call(conn, "GET", "/api/projects?q=brand",
                       token=other["token"])
        self.assertEqual(page["total"], 0)


if __name__ == "__main__":
    unittest.main()
