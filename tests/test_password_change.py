"""Password change: old password required, other sessions revoked,
current session survives, and history signed under the old key still
verifies — across a save/load round-trip too."""

import base64
import tempfile
import unittest
from pathlib import Path

from prooftrail.server import ProofTrailApp


class TestPasswordChange(unittest.TestCase):
    def _app_with_user(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        return app

    def test_change_with_correct_old_password(self):
        app = self._app_with_user()
        token = app.login("designer", "sunset-river-42")["token"]
        result = app.change_password(token, "sunset-river-42",
                                     "harbor-light-77")
        self.assertTrue(result["changed"])
        app.login("designer", "harbor-light-77")
        with self.assertRaises(Exception) as ctx:
            app.login("designer", "sunset-river-42")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)

    def test_wrong_old_password_rejected_and_unchanged(self):
        app = self._app_with_user()
        token = app.login("designer", "sunset-river-42")["token"]
        with self.assertRaises(Exception) as ctx:
            app.change_password(token, "not-my-password", "harbor-light-77")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)
        app.login("designer", "sunset-river-42")

    def test_weak_new_password_rejected_and_unchanged(self):
        app = self._app_with_user()
        token = app.login("designer", "sunset-river-42")["token"]
        with self.assertRaises(Exception) as ctx:
            app.change_password(token, "sunset-river-42", "password123")
        self.assertEqual(getattr(ctx.exception, "status", None), 400)
        app.login("designer", "sunset-river-42")

    def test_other_sessions_revoked_current_survives(self):
        app = self._app_with_user()
        token1 = app.login("designer", "sunset-river-42")["token"]
        token2 = app.login("designer", "sunset-river-42")["token"]
        app.change_password(token1, "sunset-river-42", "harbor-light-77")
        with self.assertRaises(Exception) as ctx:
            app.create_project(token2, "Nope")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)
        project = app.create_project(token1, "Still mine")
        self.assertTrue(project["project_id"])

    def test_history_verifies_across_password_change(self):
        app = self._app_with_user()
        token = app.login("designer", "sunset-river-42")["token"]
        project = app.create_project(token, "Deck")["project_id"]
        app.upload(token, project,
                   base64.b64encode(b"before change").decode())
        app.change_password(token, "sunset-river-42", "harbor-light-77")
        app.upload(token, project,
                   base64.b64encode(b"after change").decode())
        self.assertEqual(app.projects[project].verify(), [])

    def test_password_change_and_removal_survive_reload(self):
        tmp = tempfile.TemporaryDirectory()
        path = str(Path(tmp.name) / "state.json")
        app = ProofTrailApp(path)
        app.register("designer", "Designer", "sunset-river-42")
        app.register("reviewer", "Reviewer", "sunset-river-42")
        creator = app.login("designer", "sunset-river-42")["token"]
        reviewer = app.login("reviewer", "sunset-river-42")["token"]
        project = app.create_project(creator, "Deck")["project_id"]
        app.add_collaborator(creator, project, "reviewer")
        app.upload(reviewer, project,
                   base64.b64encode(b"review draft").decode())
        app.upload(creator, project,
                   base64.b64encode(b"creator draft").decode())
        app.remove_collaborator(creator, project, "reviewer")
        app.change_password(creator, "sunset-river-42", "harbor-light-77")
        app.upload(creator, project,
                   base64.b64encode(b"after change").decode())
        app._save()
        reloaded = ProofTrailApp(path)
        self.assertEqual(reloaded.projects[project].verify(), [])
        self.assertNotIn("reviewer",
                         reloaded.projects[project].collaborators)
        reloaded.login("designer", "harbor-light-77")
        tmp.cleanup()

    def test_password_change_is_audited(self):
        app = self._app_with_user()
        token = app.login("designer", "sunset-river-42")["token"]
        app.change_password(token, "sunset-river-42", "harbor-light-77")
        events = app.audit.events_for("designer")
        self.assertEqual(events[0]["event"], "password_changed")


if __name__ == "__main__":
    unittest.main()
