"""New-address logins are flagged: the first successful login from
an address an account has never used returns new_ip, and the audit
trail notes it."""

import unittest

from prooftrail.server import ProofTrailApp


class TestNewIpFlag(unittest.TestCase):
    def _app(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        return app

    def test_first_login_from_an_address_is_flagged(self):
        app = self._app()
        first = app.login("designer", "sunset-river-42",
                          remote_addr="203.0.113.7")
        self.assertTrue(first["new_ip"])
        second = app.login("designer", "sunset-river-42",
                           remote_addr="203.0.113.7")
        self.assertFalse(second["new_ip"])
        third = app.login("designer", "sunset-river-42",
                          remote_addr="198.51.100.9")
        self.assertTrue(third["new_ip"])

    def test_login_without_an_address_is_not_flagged(self):
        app = self._app()
        result = app.login("designer", "sunset-river-42")
        self.assertFalse(result["new_ip"])

    def test_flag_is_scoped_per_account(self):
        app = self._app()
        app.register("other", "Other", "sunset-river-42")
        app.login("designer", "sunset-river-42",
                  remote_addr="203.0.113.7")
        other = app.login("other", "sunset-river-42",
                          remote_addr="203.0.113.7")
        self.assertTrue(other["new_ip"])

    def test_audit_notes_the_new_address(self):
        app = self._app()
        app.login("designer", "sunset-river-42",
                  remote_addr="203.0.113.7")
        events = app.audit.events_for("designer")
        self.assertEqual(events[0]["event"], "login")
        self.assertEqual(events[0]["detail"], "new address")


if __name__ == "__main__":
    unittest.main()
