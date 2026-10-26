"""End-to-end test of the Python client against a live server."""

import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.client import ProofTrailClient, ProofTrailError
from prooftrail.server import make_server


class TestClient(unittest.TestCase):
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

    def test_full_flow_through_client(self):
        client = ProofTrailClient(f"http://127.0.0.1:{self.port}")
        self.assertEqual(client.health()["status"], "ok")
        client.register("alice-client", "Alice", "password123")
        client.login("alice-client", "password123")
        project = client.create_project("Client Project")
        pid = project["project_id"]
        version = client.upload(pid, b"client draft", label="v1",
                                filename="draft.txt")
        self.assertEqual(version["filename"], "draft.txt")
        self.assertEqual(client.versions(pid)["versions"][0]["size"], 12)
        self.assertEqual(client.version_content(pid, version["content_id"]),
                         b"client draft")
        self.assertEqual(client.verify(pid)["ledger_valid"], True)
        self.assertEqual(client.events(pid)["total"], 1)
        self.assertEqual(len(client.list_projects()["projects"]), 1)
        with self.assertRaises(ProofTrailError) as ctx:
            client.upload("no-such-project", b"x")
        self.assertEqual(ctx.exception.status, 404)
        client.logout()
        with self.assertRaises(ProofTrailError) as ctx:
            client.list_projects()
        self.assertEqual(ctx.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
