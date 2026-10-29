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


class TestServer(unittest.TestCase):
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

    def test_full_week1_flow(self):
        conn = self.conn()
        status, _ = call(conn, "POST", "/api/users",
                         {"username": "designer", "name": "Designer",
                          "password": "sunset-river-42"})
        self.assertEqual(status, 201)
        status, _ = call(conn, "POST", "/api/users",
                         {"username": "designer", "name": "Designer",
                          "password": "sunset-river-42"})
        self.assertEqual(status, 409)
        status, login = call(conn, "POST", "/api/sessions",
                             {"username": "designer", "password": "wrongpass"})
        self.assertEqual(status, 401)
        status, login = call(conn, "POST", "/api/sessions",
                             {"username": "designer", "password": "sunset-river-42"})
        self.assertEqual(status, 200)
        token = login["token"]

        # Unauthenticated project creation is refused.
        status, _ = call(conn, "POST", "/api/projects", {"title": "X"})
        self.assertEqual(status, 401)

        status, proj = call(conn, "POST", "/api/projects",
                            {"title": "Brand Deck"}, token=token)
        self.assertEqual(status, 201)
        pid = proj["project_id"]

        def upload(text, label):
            return call(conn, "POST", f"/api/projects/{pid}/uploads",
                        {"content_base64": base64.b64encode(
                            text.encode()).decode(), "label": label},
                        token=token)

        status, v1 = upload("We sell shoes.", "v1")
        self.assertEqual(status, 201)
        self.assertIsNone(v1["parent_content_id"])
        status, v2 = upload("We sell shoes. Delivery is free.", "v2")
        self.assertEqual(v2["parent_content_id"], v1["content_id"])

        status, versions = call(conn, "GET", f"/api/projects/{pid}/versions",
                                token=token)
        self.assertEqual([v["label"] for v in versions["versions"]],
                         ["v1", "v2"])

        status, page = call(conn, "GET", f"/api/projects/{pid}/verify",
                            token=token)
        self.assertTrue(page["ledger_valid"])
        self.assertNotIn("We sell shoes", json.dumps(page))

        status, content = call(
            conn, "GET",
            f"/api/projects/{pid}/versions/content"
            f"?content_id={v2['content_id']}", token=token)
        self.assertEqual(base64.b64decode(content["content_base64"]).decode(),
                         "We sell shoes. Delivery is free.")

        status, _ = call(conn, "POST", f"/api/projects/{pid}/approvals",
                         {"content_id": v2["content_id"]}, token=token)
        self.assertEqual(status, 200)
        conn.close()

    def test_only_creator_can_add_collaborators(self):
        conn = self.conn()
        # Register the creator here too (409 if the flow test already
        # did), so this test also passes run on its own.
        call(conn, "POST", "/api/users",
             {"username": "designer", "name": "Designer",
              "password": "sunset-river-42"})
        _, creator = call(conn, "POST", "/api/sessions",
                          {"username": "designer", "password": "sunset-river-42"})
        call(conn, "POST", "/api/users",
             {"username": "reviewer", "name": "Reviewer",
              "password": "sunset-river-42"})
        call(conn, "POST", "/api/users",
             {"username": "outsider", "name": "Outsider",
              "password": "sunset-river-42"})
        status, reviewer = call(conn, "POST", "/api/sessions",
                                {"username": "reviewer",
                                 "password": "sunset-river-42"})
        self.assertEqual(status, 200)
        status, proj = call(conn, "POST", "/api/projects",
                            {"title": "Guarded"}, token=creator["token"])
        pid = proj["project_id"]
        status, _ = call(conn, "POST", f"/api/projects/{pid}/collaborators",
                         {"username": "reviewer"}, token=creator["token"])
        self.assertEqual(status, 200)
        # A non-creator collaborator cannot invite anyone else.
        status, err = call(conn, "POST",
                           f"/api/projects/{pid}/collaborators",
                           {"username": "outsider"}, token=reviewer["token"])
        self.assertEqual(status, 403)
        self.assertIn("creator", err["error"])
        # The creator still can.
        status, _ = call(conn, "POST", f"/api/projects/{pid}/collaborators",
                         {"username": "outsider"}, token=creator["token"])
        self.assertEqual(status, 200)
        conn.close()


if __name__ == "__main__":
    unittest.main()
