"""Authentication audit trail: auth events are recorded, and each
user sees only their own through GET /api/sessions/audit."""

import unittest

from prooftrail.auth import AuditLog
from prooftrail.server import ProofTrailApp


class TestAuditLog(unittest.TestCase):
    def test_events_recorded_newest_first(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        token = app.login("designer", "sunset-river-42",
                          remote_addr="203.0.113.7")["token"]
        app.logout(token)
        # The token was revoked by logout, so query via a fresh login.
        token2 = app.login("designer", "sunset-river-42")["token"]
        events = app.audit_for(token2)["events"]
        kinds = [e["event"] for e in events]
        self.assertEqual(kinds, ["login", "logout", "login", "register"])
        self.assertEqual(events[2]["remote_addr"], "203.0.113.7")
        self.assertTrue(all(e["actor_id"] == "designer" for e in events))

    def test_failed_logins_and_lockout_recorded(self):
        app = ProofTrailApp()
        app.register("victim", "Victim", "sunset-river-42")
        for _ in range(5):
            with self.assertRaises(Exception):
                app.login("victim", "wrong-password")
        kinds = [e["event"] for e in app.audit.events_for("victim")]
        self.assertEqual(kinds.count("login_failed"), 5)
        self.assertIn("lockout", kinds)

    def test_users_see_only_their_own_events(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        app.register("other", "Other", "sunset-river-42")
        token = app.login("designer", "sunset-river-42")["token"]
        events = app.audit_for(token)["events"]
        self.assertTrue(all(e["actor_id"] == "designer" for e in events))
        self.assertTrue(events)

    def test_audit_requires_authentication(self):
        app = ProofTrailApp()
        with self.assertRaises(Exception) as ctx:
            app.audit_for(None)
        self.assertEqual(getattr(ctx.exception, "status", None), 401)

    def test_log_is_capped(self):
        log = AuditLog(max_events=3)
        for i in range(5):
            log.record("login", "designer", detail=str(i))
        events = log.events_for("designer")
        self.assertEqual(len(events), 3)
        self.assertEqual([e["detail"] for e in events], ["4", "3", "2"])


if __name__ == "__main__":
    unittest.main()
