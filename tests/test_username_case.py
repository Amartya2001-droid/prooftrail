import unittest

from prooftrail.server import ApiError, ProofTrailApp


class TestUsernameCase(unittest.TestCase):
    def setUp(self):
        self.app = ProofTrailApp()

    def test_register_normalizes_to_lowercase(self):
        result = self.app.register("Designer", "Designer", "sunset-river-42")
        self.assertEqual(result["actor_id"], "designer")
        self.assertIn("designer", self.app.users)

    def test_case_variant_is_a_duplicate(self):
        self.app.register("designer", "Designer", "sunset-river-42")
        with self.assertRaises(ApiError) as ctx:
            self.app.register("DESIGNER", "Impostor", "sunset-river-42")
        self.assertEqual(ctx.exception.status, 409)

    def test_login_is_case_insensitive(self):
        self.app.register("designer", "Designer", "sunset-river-42")
        result = self.app.login("DeSiGnEr", "sunset-river-42")
        self.assertEqual(result["actor_id"], "designer")

    def test_add_collaborator_is_case_insensitive(self):
        self.app.register("designer", "Designer", "sunset-river-42")
        self.app.register("reviewer", "Reviewer", "sunset-river-42")
        token = self.app.login("designer", "sunset-river-42")["token"]
        pid = self.app.create_project(token, "Brand Deck")["project_id"]
        result = self.app.add_collaborator(token, pid, "REVIEWER")
        self.assertEqual(result["collaborator"], "reviewer")


if __name__ == "__main__":
    unittest.main()
