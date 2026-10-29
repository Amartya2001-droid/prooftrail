"""Session binding: a session created with a client address and user
agent stops working — and is revoked — when presented from elsewhere."""

import unittest

from prooftrail.auth import SessionStore
from prooftrail.server import ProofTrailApp


class TestSessionBindingStore(unittest.TestCase):
    def test_same_client_keeps_working(self):
        store = SessionStore()
        token = store.create("designer", "203.0.113.7", "Agent/1.0")
        self.assertEqual(
            store.lookup(token, "203.0.113.7", "Agent/1.0"), "designer")

    def test_different_address_revokes_the_token(self):
        store = SessionStore()
        token = store.create("designer", "203.0.113.7", "Agent/1.0")
        self.assertIsNone(store.lookup(token, "198.51.100.9", "Agent/1.0"))
        # Revoked, not merely rejected: the original client is locked
        # out too, so a stolen token cannot be retried.
        self.assertIsNone(store.lookup(token, "203.0.113.7", "Agent/1.0"))

    def test_different_agent_revokes_the_token(self):
        store = SessionStore()
        token = store.create("designer", "203.0.113.7", "Agent/1.0")
        self.assertIsNone(store.lookup(token, "203.0.113.7", "Agent/2.0"))
        self.assertIsNone(store.lookup(token, "203.0.113.7", "Agent/1.0"))

    def test_unbound_sessions_and_lookups_skip_the_check(self):
        store = SessionStore()
        token = store.create("designer")
        self.assertEqual(store.lookup(token, "203.0.113.7", "Agent/1.0"),
                         "designer")
        bound = store.create("designer", "203.0.113.7", "Agent/1.0")
        self.assertEqual(store.lookup(bound), "designer")


class TestSessionBindingApp(unittest.TestCase):
    def _logged_in(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        token = app.login("designer", "sunset-river-42",
                          remote_addr="203.0.113.7",
                          user_agent="Agent/1.0")["token"]
        return app, token

    def test_same_client_can_use_the_token(self):
        app, token = self._logged_in()
        with app.request_context("203.0.113.7", "Agent/1.0"):
            project = app.create_project(token, "Bound Project")
        self.assertTrue(project["project_id"])

    def test_other_address_gets_401_and_token_is_revoked(self):
        app, token = self._logged_in()
        with app.request_context("198.51.100.9", "Agent/1.0"):
            with self.assertRaises(Exception) as ctx:
                app.create_project(token, "Nope")
            self.assertEqual(getattr(ctx.exception, "status", None), 401)
        with app.request_context("203.0.113.7", "Agent/1.0"):
            with self.assertRaises(Exception) as ctx:
                app.create_project(token, "Nope")
            self.assertEqual(getattr(ctx.exception, "status", None), 401)

    def test_other_agent_gets_401(self):
        app, token = self._logged_in()
        with app.request_context("203.0.113.7", "Agent/2.0"):
            with self.assertRaises(Exception) as ctx:
                app.create_project(token, "Nope")
            self.assertEqual(getattr(ctx.exception, "status", None), 401)


if __name__ == "__main__":
    unittest.main()
