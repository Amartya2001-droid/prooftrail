import unittest

from prooftrail.store import Actor, Project


class TestStore(unittest.TestCase):
    def setUp(self):
        self.designer = Actor.create("designer", "Freelance Designer")
        self.client = Actor.create("client", "Client")
        self.project = Project("brand-deck", "Brand Deck")
        self.project.add_collaborator(self.designer)
        self.project.add_collaborator(self.client)

    def test_upload_links_parents_and_verifies(self):
        v1 = self.project.upload(self.designer, b"v1 content", "2026-10-24T10:00:00Z", "v1")
        v2 = self.project.upload(self.designer, b"v2 content", "2026-10-24T11:00:00Z", "v2")
        self.assertIsNone(v1.parent_content_id)
        self.assertEqual(v2.parent_content_id, v1.content_id)
        self.assertEqual(self.project.read(v2), b"v2 content")
        self.assertEqual(self.project.verify(), [])

    def test_approval_event_recorded(self):
        v1 = self.project.upload(self.designer, b"v1", "2026-10-24T10:00:00Z")
        self.project.approve(self.client, v1, "2026-10-24T12:00:00Z")
        types = [e["type"] for e in self.project.ledger.events]
        self.assertEqual(types, ["upload", "approval"])
        self.assertEqual(self.project.verify(), [])

    def test_non_collaborator_cannot_upload(self):
        outsider = Actor.create("outsider", "Outsider")
        with self.assertRaises(ValueError):
            self.project.upload(outsider, b"x", "2026-10-24T10:00:00Z")


if __name__ == "__main__":
    unittest.main()
