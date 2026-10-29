"""Login timing: rejecting an unknown username must cost the same
password-checking work as rejecting a wrong password for a real user,
or the timing difference alone enumerates accounts."""

import unittest

import prooftrail.auth as auth_module
from prooftrail.server import ProofTrailApp


class TestLoginTiming(unittest.TestCase):
    def test_unknown_user_costs_the_same_pbkdf2_work(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")

        original = auth_module._pbkdf2
        calls = []

        def counting(password, salt):
            calls.append(1)
            return original(password, salt)

        auth_module._pbkdf2 = counting
        try:
            with self.assertRaises(Exception):
                app.login("ghost", "some-password")
            unknown_calls = len(calls)
            calls.clear()
            with self.assertRaises(Exception):
                app.login("designer", "wrong-password")
            known_wrong_calls = len(calls)
        finally:
            auth_module._pbkdf2 = original
        self.assertEqual(unknown_calls, known_wrong_calls)
        self.assertEqual(unknown_calls, 1)

    def test_unknown_user_still_gets_generic_error(self):
        app = ProofTrailApp()
        app.register("designer", "Designer", "sunset-river-42")
        with self.assertRaises(Exception) as ctx:
            app.login("ghost", "some-password")
        self.assertEqual(getattr(ctx.exception, "status", None), 401)


if __name__ == "__main__":
    unittest.main()
