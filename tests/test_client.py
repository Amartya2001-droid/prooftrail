"""End-to-end test of the Python client against a live server."""

import tempfile
import threading
import time
import unittest
from pathlib import Path

from prooftrail.auth import totp_code
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
        client.register("alice-client", "Alice", "sunset-river-42")
        client.login("alice-client", "sunset-river-42")
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

    def test_newer_auth_and_session_endpoints_through_client(self):
        client = ProofTrailClient(f"http://127.0.0.1:{self.port}")
        client.register("bob-client", "Bob", "sunset-river-42")
        client.login("bob-client", "sunset-river-42")
        second = ProofTrailClient(f"http://127.0.0.1:{self.port}")
        second.login("bob-client", "sunset-river-42")

        sessions = client.sessions()["sessions"]
        self.assertEqual(len(sessions), 2)
        current = [s for s in sessions if s["current"]]
        self.assertEqual(len(current), 1)
        other = [s for s in sessions if not s["current"]][0]
        self.assertEqual(client.revoke_session(other["session_id"]),
                         {"revoked": True})
        with self.assertRaises(ProofTrailError) as ctx:
            second.list_projects()
        self.assertEqual(ctx.exception.status, 401)
        audit_kinds = [e["event"] for e in client.audit()["events"]]
        self.assertIn("login", audit_kinds)
        self.assertIn("session_revoked", audit_kinds)

        project = client.create_project("Bob Project")
        pid = project["project_id"]
        client.register("carol-client", "Carol", "sunset-river-42")
        client.add_collaborator(pid, "carol-client")
        removed = client.remove_collaborator(pid, "carol-client")
        self.assertEqual(removed["removed"], "carol-client")
        self.assertEqual(removed["project_id"], pid)

        self.assertEqual(client.change_password(
            "sunset-river-42", "moonlit-lake-99"), {"changed": True})
        with self.assertRaises(ProofTrailError):
            client.login("bob-client", "sunset-river-42")
        client.login("bob-client", "moonlit-lake-99")

        setup = client.totp_setup()
        code = totp_code(setup["secret"], time.time())
        confirmed = client.totp_confirm(code)
        self.assertTrue(confirmed["enabled"])
        self.assertEqual(len(confirmed["recovery_codes"]), 10)
        pending = client.login("bob-client", "moonlit-lake-99")
        self.assertIsNone(client.token)
        # The confirm step's code cannot be reused (reuse within a
        # step is rejected), so verify with the next step's code.
        # A fixed +35 seconds could land two steps ahead when the
        # confirm happened near a step boundary, so compute the
        # first second of the next step explicitly: the server
        # accepts it within one step of clock skew, and it is
        # never the confirm step.
        now = time.time()
        next_step_start = (int(now // 30) + 1) * 30
        code = totp_code(setup["secret"], next_step_start + 1)
        client.totp_verify(pending, code=code)
        self.assertIsNotNone(client.token)
        self.assertTrue(client.totp_disable("moonlit-lake-99")["disabled"])

        spec = client.openapi()
        self.assertIn("/api/sessions/revoke-one", spec["paths"])
        self.assertIn("/api/users/totp/confirm", spec["paths"])


if __name__ == "__main__":
    unittest.main()
