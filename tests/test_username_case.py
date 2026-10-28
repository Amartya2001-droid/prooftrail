import unittest

from prooftrail.server import ApiError, ProofTrailApp


class TestUsernameCase(unittest.TestCase):
    def setUp(self):
        self.app = ProofTrailApp()

    def test_register_normalizes_to_lowercase(self):
        result = self.app.register("Designer", "Designer", "password123")
        self.assertEqual(result["actor_id"], "designer")
        self.assertIn("designer", self.app.users)

    def test_case_variant_is_a_duplicate(self):
        self.app.register("designer", "Designer", "password123")
        with self.assertRaises(ApiError) as ctx:
            self.app.register("DESIGNER", "Impostor", "password123")
        self.assertEqual(ctx.exception.status, 409)

    def test_login_is_case_insensitive(self):
        self.app.register("designer", "Designer", "password123")
        result = self.app.login("DeSiGnEr", "password123")
        self.assertEqual(result["actor_id"], "designer")

    def test_add_collaborator_is_case_insensitive(self):
        self.app.register("designer", "Designer", "password123")
        self.app.register("reviewer", "Reviewer", "password123")
        token = self.app.login("designer", "password123")["token"]
        pid = self.app.create_project(token, "Brand Deck")["project_id"]
        result = self.app.add_collaborator(token, pid, "REVIEWER")
        self.assertEqual(result["collaborator"], "reviewer")


if __name__ == "__main__":
    unittest.main()
