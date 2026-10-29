"""Individual session control: list your sessions (tokens never
exposed) and revoke one by id, without logging out everywhere."""

import unittest

from prooftrail.server import ProofTrailApp


class TestSessionList(unittest.TestCase):
    def _two_sessions(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        app.register("other", "Other", "sunset-river-42")
        token1 = app.login("designer", "sunset-river-42",
                           user_agent="Laptop/1.0")["token"]
        token2 = app.login("designer", "sunset-river-42",
                           user_agent="Phone/2.0")["token"]
        return app, token1, token2

    def test_list_shows_both_sessions_without_tokens(self):
        app, token1, token2 = self._two_sessions()
        sessions = app.sessions_for(token1)["sessions"]
        self.assertEqual(len(sessions), 2)
        self.assertEqual({s["label"] for s in sessions},
                         {"Laptop/1.0", "Phone/2.0"})
        for session in sessions:
            self.assertNotIn("token", session)
            self.assertNotIn(token1, str(session.values()))
            self.assertNotIn(token2, str(session.values()))
        current = [s for s in sessions if s["current"]]
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]["label"], "Laptop/1.0")

    def test_revoke_one_kills_only_that_session(self):
        app, token1, token2 = self._two_sessions()
        sessions = app.sessions_for(token1)["sessions"]
        other_id = next(s["session_id"] for s in sessions
                        if s["label"] == "Phone/2.0")
        result = app.revoke_session(token1, other_id)
        self.assertTrue(result["revoked"])
        with self.assertRaises(Exception) as ctx:
            app.create_project(token2, "Nope")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)
        project = app.create_project(token1, "Still mine")
        self.assertTrue(project["project_id"])

    def test_revoke_unknown_or_foreign_session_is_404(self):
        app, token1, _ = self._two_sessions()
        with self.assertRaises(Exception) as ctx:
            app.revoke_session(token1, "no-such-session")
        self.assertEqual(getattr(ctx.exception, "status", None), 404)
        other_token = app.login("other", "sunset-river-42")["token"]
        foreign_id = app.sessions_for(other_token)["sessions"][0]["session_id"]
        with self.assertRaises(Exception) as ctx:
            app.revoke_session(token1, foreign_id)
        self.assertEqual(getattr(ctx.exception, "status", None), 404)

    def test_list_requires_authentication(self):
        app = ProofTrailApp()
        with self.assertRaises(Exception) as ctx:
            app.sessions_for(None)
        self.assertEqual(getattr(ctx.exception, "status", None), 401)


if __name__ == "__main__":
    unittest.main()
