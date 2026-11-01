"""Listing a project's collaborators: any collaborator may see who
else can read the project's history, names only, creator flagged."""

import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.client import ProofTrailClient
from prooftrail.server import ProofTrailApp, make_server


class TestCollaboratorsListing(unittest.TestCase):
    def setUp(self):
        self.app = ProofTrailApp()
        self.app.register("designer", "Designer", "sunset-river-42")
        self.app.register("reviewer", "Reviewer", "sunset-river-42")
        self.app.register("outsider", "Outsider", "sunset-river-42")
        self.token = self.app.login(
            "designer", "sunset-river-42")["token"]
        self.pid = self.app.create_project(self.token, "Show")["project_id"]

    def test_creator_listed_and_flagged(self):
        listed = self.app.collaborators_for(self.token, self.pid)
        self.assertEqual(listed["collaborators"], [
            {"actor_id": "designer", "name": "Designer",
             "is_creator": True}])

    def test_added_then_removed_collaborator(self):
        self.app.add_collaborator(self.token, self.pid, "reviewer")
        listed = self.app.collaborators_for(self.token, self.pid)
        self.assertEqual(
            [c["actor_id"] for c in listed["collaborators"]],
            ["designer", "reviewer"])
        self.assertFalse(listed["collaborators"][1]["is_creator"])
        self.app.remove_collaborator(self.token, self.pid, "reviewer")
        listed = self.app.collaborators_for(self.token, self.pid)
        self.assertEqual(
            [c["actor_id"] for c in listed["collaborators"]],
            ["designer"])

    def test_non_collaborator_cannot_list(self):
        token = self.app.login("outsider", "sunset-river-42")["token"]
        with self.assertRaises(Exception) as ctx:
            self.app.collaborators_for(token, self.pid)
        self.assertEqual(getattr(ctx.exception, "status", None), 403)

    def test_listing_requires_authentication(self):
        with self.assertRaises(Exception) as ctx:
            self.app.collaborators_for(None, self.pid)
        self.assertEqual(getattr(ctx.exception, "status", None), 401)


class TestCollaboratorsListingHttp(unittest.TestCase):
    def test_list_through_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            server, _ = make_server("127.0.0.1", 0,
                                    str(Path(tmp) / "state.json"))
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            try:
                client = ProofTrailClient(f"http://127.0.0.1:{port}")
                client.register("designer", "Designer", "sunset-river-42")
                client.login("designer", "sunset-river-42")
                pid = client.create_project("Show")["project_id"]
                client.register("reviewer", "Reviewer", "sunset-river-42")
                client.add_collaborator(pid, "reviewer")
                listed = client.collaborators(pid)["collaborators"]
                self.assertEqual(
                    [(c["actor_id"], c["is_creator"]) for c in listed],
                    [("designer", True), ("reviewer", False)])
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
