"""Regenerating TOTP recovery codes: a lost list is replaceable,
and the old codes stop working the moment new ones are issued."""

import time
import unittest

from prooftrail.auth import totp_code
from prooftrail.server import ProofTrailApp


def fresh_code(secret: str) -> str:
    """A code from the *next* 30-second step (see test_totp.py)."""
    step = int(time.time()) // 30 + 1
    return totp_code(secret, step * 30 + 1)


class TestRecoveryRegeneration(unittest.TestCase):
    def _enabled_app(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        token = app.login("designer", "sunset-river-42")["token"]
        setup = app.totp_setup(token)
        code = totp_code(setup["secret"], time.time())
        result = app.totp_confirm(token, code)
        return app, token, setup["secret"], result["recovery_codes"]

    def test_regeneration_replaces_the_old_codes(self):
        app, token, _, old_codes = self._enabled_app()
        result = app.regenerate_recovery_codes(
            token, "sunset-river-42")
        new_codes = result["recovery_codes"]
        self.assertEqual(len(new_codes), len(old_codes))
        self.assertNotEqual(set(new_codes), set(old_codes))
        # An old code no longer signs in.
        with self.assertRaises(Exception) as ctx:
            app.login("designer", "sunset-river-42",
                      recovery_code=old_codes[0])
        self.assertEqual(getattr(ctx.exception, "status", None), 401)
        # A new code does, once.
        logged_in = app.login("designer", "sunset-river-42",
                              recovery_code=new_codes[0])
        self.assertIn("token", logged_in)
        with self.assertRaises(Exception) as ctx:
            app.login("designer", "sunset-river-42",
                      recovery_code=new_codes[0])
        self.assertEqual(getattr(ctx.exception, "status", None), 401)

    def test_wrong_password_leaves_old_codes_working(self):
        app, token, _, old_codes = self._enabled_app()
        with self.assertRaises(Exception) as ctx:
            app.regenerate_recovery_codes(token, "wrong-password")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)
        logged_in = app.login("designer", "sunset-river-42",
                              recovery_code=old_codes[0])
        self.assertIn("token", logged_in)

    def test_regeneration_requires_totp_enabled(self):
        app = ProofTrailApp()
        app.register("plain", "Plain", "sunset-river-42")
        token = app.login("plain", "sunset-river-42")["token"]
        with self.assertRaises(Exception) as ctx:
            app.regenerate_recovery_codes(token, "sunset-river-42")
        self.assertEqual(getattr(ctx.exception, "status", None), 400)

    def test_regeneration_is_audited(self):
        app, token, _, _ = self._enabled_app()
        app.regenerate_recovery_codes(token, "sunset-river-42")
        trail = app.audit_for(token)
        self.assertIn("totp_recovery_regenerated",
                      [e["event"] for e in trail["events"]])


if __name__ == "__main__":
    unittest.main()
