"""Collaborator removal: creator-only, immediate, and history stays
verifiable — removal ends access, never the past ledger."""

import base64
import unittest

from prooftrail.server import ProofTrailApp


class TestCollaboratorRemoval(unittest.TestCase):
    def _setup(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        app.register("reviewer", "Reviewer", "sunset-river-42")
        creator = app.login("designer", "sunset-river-42")["token"]
        reviewer = app.login("reviewer", "sunset-river-42")["token"]
        project = app.create_project(creator, "Deck")["project_id"]
        app.add_collaborator(creator, project, "reviewer")
        return app, creator, reviewer, project

    def test_removed_collaborator_loses_access_immediately(self):
        app, creator, reviewer, project = self._setup()
        app.upload(reviewer, project,
                   base64.b64encode(b"review draft").decode())
        app.remove_collaborator(creator, project, "reviewer")
        with self.assertRaises(Exception) as ctx:
            app.upload(reviewer, project,
                       base64.b64encode(b"more").decode())
        self.assertEqual(getattr(ctx.exception, "status", None), 403)
        with self.assertRaises(Exception) as ctx:
            app.versions(reviewer, project)
        self.assertEqual(getattr(ctx.exception, "status", None), 403)

    def test_non_creator_cannot_remove(self):
        app, creator, reviewer, project = self._setup()
        with self.assertRaises(Exception) as ctx:
            app.remove_collaborator(reviewer, project, "designer")
        self.assertEqual(getattr(ctx.exception, "status", None), 403)

    def test_creator_cannot_remove_self(self):
        app, creator, _, project = self._setup()
        with self.assertRaises(Exception) as ctx:
            app.remove_collaborator(creator, project, "designer")
        self.assertEqual(getattr(ctx.exception, "status", None), 400)

    def test_removing_a_non_collaborator_is_404(self):
        app, creator, _, project = self._setup()
        with self.assertRaises(Exception) as ctx:
            app.remove_collaborator(creator, project, "ghost")
        self.assertEqual(getattr(ctx.exception, "status", None), 404)

    def test_history_still_verifies_and_readd_works(self):
        app, creator, reviewer, project = self._setup()
        app.upload(reviewer, project,
                   base64.b64encode(b"review draft").decode())
        app.remove_collaborator(creator, project, "reviewer")
        self.assertEqual(app.projects[project].verify(), [])
        app.add_collaborator(creator, project, "reviewer")
        app.upload(reviewer, project,
                   base64.b64encode(b"back again").decode())
        self.assertEqual(app.projects[project].verify(), [])


if __name__ == "__main__":
    unittest.main()
