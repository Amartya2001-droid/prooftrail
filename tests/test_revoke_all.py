import unittest

from prooftrail.server import ApiError, ProofTrailApp


class TestRevokeAll(unittest.TestCase):
    def setUp(self):
        self.app = ProofTrailApp()
        self.app.register("designer", "Designer", "password123")
        self.app.register("other", "Other", "password123")

    def test_revoke_all_kills_every_session_for_the_user(self):
        token1 = self.app.login("designer", "password123")["token"]
        token2 = self.app.login("designer", "password123")["token"]
        other_token = self.app.login("other", "password123")["token"]
        result = self.app.logout_all(token1)
        self.assertEqual(result, {"revoked": 2})
        for dead in (token1, token2):
            with self.assertRaises(ApiError) as ctx:
                self.app.list_projects(dead)
            self.assertEqual(ctx.exception.status, 401)
        # Another user's session is untouched.
        self.app.list_projects(other_token)

    def test_revoke_all_without_a_token_is_unauthorized(self):
        with self.assertRaises(ApiError) as ctx:
            self.app.logout_all(None)
        self.assertEqual(ctx.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
