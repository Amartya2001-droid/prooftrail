"""Registration password policy: common passwords and the username
itself as password are rejected; strong passwords are accepted."""

import unittest

from prooftrail.server import ProofTrailApp


class TestPasswordPolicy(unittest.TestCase):
    def test_common_passwords_rejected(self):
        app = ProofTrailApp()
        for i, weak in enumerate(["password123", "Password123",
                                  "qwerty123", "welcome1", "admin123"]):
            with self.assertRaises(Exception) as ctx:
                app.register(f"user{i}", "User", weak)
            self.assertEqual(getattr(ctx.exception, "status", None), 400)

    def test_username_as_password_rejected(self):
        app = ProofTrailApp()
        with self.assertRaises(Exception) as ctx:
            app.register("longusername", "User", "longusername")
        self.assertEqual(getattr(ctx.exception, "status", None), 400)

    def test_short_password_still_rejected(self):
        app = ProofTrailApp()
        with self.assertRaises(Exception) as ctx:
            app.register("user", "User", "short")
        self.assertEqual(getattr(ctx.exception, "status", None), 400)

    def test_strong_password_accepted_and_logs_in(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        result = app.login("designer", "sunset-river-42")
        self.assertEqual(result["actor_id"], "designer")
        self.assertTrue(result["token"])


if __name__ == "__main__":
    unittest.main()
