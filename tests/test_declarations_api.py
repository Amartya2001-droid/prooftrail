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


class TestDeclarationsApi(unittest.TestCase):
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
              "password": "password123"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": username, "password": "password123"})
        return login["token"]

    def test_declarations_flow(self):
        conn = self.conn()
        token = self._login(conn, "designer")
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": "Brand Deck"}, token=token)
        pid = proj["project_id"]

        def upload(text, label):
            return call(conn, "POST", f"/api/projects/{pid}/uploads",
                        {"content_base64": base64.b64encode(
                            text.encode()).decode(), "label": label},
                        token=token)

        _, v1 = upload("We sell shoes.", "v1")
        _, v2 = upload("We sell shoes. Delivery is free.", "v2")

        # Unknown version -> 404; bad sentence index -> 400.
        status, _ = call(conn, "POST", f"/api/projects/{pid}/declarations",
                         {"content_id": "0" * 64, "tool": "ChatGPT"},
                         token=token)
        self.assertEqual(status, 404)
        status, _ = call(conn, "POST", f"/api/projects/{pid}/declarations",
                         {"content_id": v2["content_id"], "tool": "ChatGPT",
                          "sentence_indices": [5]}, token=token)
        self.assertEqual(status, 400)

        status, decl = call(conn, "POST", f"/api/projects/{pid}/declarations",
                            {"content_id": v2["content_id"], "tool": "ChatGPT",
                             "prompt_summary": "wrote the delivery line",
                             "sentence_indices": [1]}, token=token)
        self.assertEqual(status, 201)
        self.assertEqual(decl["tool"], "ChatGPT")

        status, decls = call(conn, "GET", f"/api/projects/{pid}/declarations",
                             token=token)
        self.assertEqual(len(decls["declarations"]), 1)
        self.assertEqual(decls["declarations"][0]["version_label"], "v2")

        # The contribution map keeps one segment per sentence per version:
        # v1's sentence, then v2 carrying it forward plus the declared one.
        status, cmap = call(conn, "GET", f"/api/projects/{pid}/contributions",
                            token=token)
        self.assertEqual(
            [s["source"] for s in cmap["segments"]],
            ["human", "human", "ai-assisted"])
        self.assertGreater(cmap["coverage_pct"]["ai-assisted"], 0)
        self.assertIn("not proof of authorship", cmap["caveat"])

        status, page = call(conn, "GET", f"/api/projects/{pid}/verify",
                            token=token)
        self.assertGreater(
            page["contribution_coverage_pct"]["ai-assisted"], 0)
        self.assertTrue(page["ledger_valid"])

        # A non-collaborator gets 403, not the declarations.
        outsider = self._login(conn, "outsider")
        status, _ = call(conn, "GET", f"/api/projects/{pid}/declarations",
                         token=outsider)
        self.assertEqual(status, 403)
        conn.close()


if __name__ == "__main__":
    unittest.main()
