import base64
import unittest

from prooftrail.server import ApiError, ProofTrailApp


class TestUploadGuards(unittest.TestCase):
    def setUp(self):
        self.app = ProofTrailApp()
        self.app.register("designer", "Designer", "password123")
        token = self.app.login("designer", "password123")["token"]
        self.token = token
        self.pid = self.app.create_project(token, "Brand Deck")["project_id"]

    def test_empty_upload_is_rejected(self):
        with self.assertRaises(ApiError) as ctx:
            self.app.upload(self.token, self.pid, "")
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn("empty", ctx.exception.message)

    def test_empty_upload_adds_no_version_or_event(self):
        with self.assertRaises(ApiError):
            self.app.upload(self.token, self.pid, "")
        project = self.app.projects[self.pid]
        self.assertEqual(project.versions, [])
        self.assertEqual(project.ledger.events, [])

    def test_nonempty_upload_still_works(self):
        result = self.app.upload(
            self.token, self.pid,
            base64.b64encode(b"hello").decode(), label="v1")
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["size"], 5)


if __name__ == "__main__":
    unittest.main()
