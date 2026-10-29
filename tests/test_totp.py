"""Optional TOTP second factor: enrollment confirmed by a code before
it takes effect, a short-lived pending login, same-step replay
rejection, and hashed single-use recovery codes."""

import time
import unittest

from prooftrail.auth import UserRecord, totp_code
from prooftrail.server import ProofTrailApp


def fresh_code(secret: str) -> str:
    """A code from the *next* 30-second step.

    Enrollment confirmation consumes the current step's code (replay
    protection), so a code for the current step would be the same
    code again and correctly rejected. The next step's code is always
    within the ±1-step acceptance window at verify time.
    """
    step = int(time.time()) // 30 + 1
    return totp_code(secret, step * 30 + 1)


class TestTotp(unittest.TestCase):
    def _enabled_app(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        token = app.login("designer", "sunset-river-42")["token"]
        setup = app.totp_setup(token)
        code = totp_code(setup["secret"], time.time())
        result = app.totp_confirm(token, code)
        return app, token, setup["secret"], result["recovery_codes"]

    def test_setup_does_not_enable_until_confirm(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        token = app.login("designer", "sunset-river-42")["token"]
        app.totp_setup(token)
        # Password-only login still works before confirmation.
        self.assertIn("token", app.login("designer", "sunset-river-42"))

    def test_confirm_with_wrong_code_fails(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        token = app.login("designer", "sunset-river-42")["token"]
        app.totp_setup(token)
        with self.assertRaises(Exception) as ctx:
            app.totp_confirm(token, "000000")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)
        self.assertIn("token", app.login("designer", "sunset-river-42"))

    def test_pending_login_then_verify(self):
        app, _, secret, _ = self._enabled_app()
        pending = app.login("designer", "sunset-river-42")
        self.assertTrue(pending["totp_required"])
        self.assertNotIn("token", pending)
        result = app.totp_verify(pending["pending_token"],
                                 fresh_code(secret))
        self.assertIn("token", result)
        project = app.create_project(result["token"], "Secured")
        self.assertTrue(project["project_id"])

    def test_login_with_code_inline(self):
        app, _, secret, _ = self._enabled_app()
        result = app.login("designer", "sunset-river-42",
                           totp_code=fresh_code(secret))
        self.assertIn("token", result)

    def test_wrong_code_fails_and_pending_survives_for_retry(self):
        app, _, secret, _ = self._enabled_app()
        pending = app.login("designer", "sunset-river-42")
        with self.assertRaises(Exception) as ctx:
            app.totp_verify(pending["pending_token"], "000000")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)
        result = app.totp_verify(pending["pending_token"],
                                 fresh_code(secret))
        self.assertIn("token", result)

    def test_code_cannot_be_replayed_in_the_same_step(self):
        app, _, secret, _ = self._enabled_app()
        code = fresh_code(secret)
        first = app.login("designer", "sunset-river-42")
        app.totp_verify(first["pending_token"], code)
        second = app.login("designer", "sunset-river-42")
        with self.assertRaises(Exception) as ctx:
            app.totp_verify(second["pending_token"], code)
        self.assertEqual(getattr(ctx.exception, "status", None), 401)

    def test_recovery_code_works_once(self):
        app, _, _, codes = self._enabled_app()
        pending = app.login("designer", "sunset-river-42")
        result = app.totp_verify(pending["pending_token"],
                                 recovery_code=codes[0])
        self.assertIn("token", result)
        pending2 = app.login("designer", "sunset-river-42")
        with self.assertRaises(Exception) as ctx:
            app.totp_verify(pending2["pending_token"],
                            recovery_code=codes[0])
        self.assertEqual(getattr(ctx.exception, "status", None), 401)

    def test_recovery_codes_are_stored_hashed(self):
        app, _, _, codes = self._enabled_app()
        stored = app.users["designer"].recovery_codes
        self.assertEqual(len(stored), 10)
        self.assertTrue(all(c not in stored for c in codes))

    def test_disable_with_password_restores_password_only_login(self):
        app, token, _, _ = self._enabled_app()
        result = app.totp_disable(token, "sunset-river-42")
        self.assertTrue(result["disabled"])
        self.assertIn("token", app.login("designer", "sunset-river-42"))

    def test_disable_with_wrong_password_fails(self):
        app, token, _, _ = self._enabled_app()
        with self.assertRaises(Exception) as ctx:
            app.totp_disable(token, "not-my-password")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)
        pending = app.login("designer", "sunset-river-42")
        self.assertTrue(pending["totp_required"])

    def test_old_state_files_load_without_totp(self):
        record = UserRecord.from_dict({
            "username": "designer", "name": "Designer",
            "actor_id": "designer",
            "salt_auth": "00" * 16, "salt_key": "00" * 16,
            "verifier": "00" * 32, "public_key": "00" * 32,
        })
        self.assertFalse(record.totp_enabled)
        self.assertEqual(record.totp_secret, "")
        self.assertEqual(record.recovery_codes, [])


if __name__ == "__main__":
    unittest.main()
