import tempfile
import unittest
from pathlib import Path

from prooftrail.auth import create_user
from prooftrail.persistence import load_state, save_state
from prooftrail.store import Actor, Project


class TestPersistence(unittest.TestCase):
    def test_save_load_roundtrip_keeps_history_verifiable(self):
        designer = Actor.create("designer", "Freelance Designer")
        client = Actor.create("client", "Client")
        project = Project("brand-deck", "Brand Deck")
        project.add_collaborator(designer)
        project.add_collaborator(client)
        project.upload(designer, b"v1", "2026-10-24T10:00:00Z", "v1")
        project.upload(designer, b"v2", "2026-10-24T11:00:00Z", "v2")
        project.approve(client, project.versions[1], "2026-10-24T12:00:00Z")
        users = {"designer": create_user("designer", "Freelance Designer", "pw")}

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            save_state(path, users, {"brand-deck": project})
            loaded_users, loaded_projects = load_state(path)

        loaded = loaded_projects["brand-deck"]
        self.assertEqual(loaded.verify(), [])
        self.assertEqual([v.label for v in loaded.history()], ["v1", "v2"])
        self.assertEqual(loaded.read(loaded.versions[1]), b"v2")
        self.assertEqual(len(loaded.ledger.events), 3)
        self.assertIn("designer", loaded_users)

    def test_missing_file_is_empty_state(self):
        users, projects = load_state("/tmp/definitely-not-here-prooftrail.json")
        self.assertEqual((users, projects), ({}, {}))

    def test_tampered_event_payload_is_refused_at_load(self):
        designer = Actor.create("designer", "Freelance Designer")
        project = Project("brand-deck", "Brand Deck")
        project.add_collaborator(designer)
        project.upload(designer, b"v1", "2026-10-24T10:00:00Z", "v1")
        users = {"designer": create_user("designer", "Freelance Designer", "pw")}

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            save_state(path, users, {"brand-deck": project})
            # Rewrite one event's payload without re-signing: the chain
            # hash and signature no longer match the stored event.
            import json

            state = json.loads(path.read_text())
            state["projects"]["brand-deck"]["events"][0]["payload"] = {
                "label": "forged"}
            path.write_text(json.dumps(state))
            with self.assertRaises(ValueError) as ctx:
                load_state(path)
            self.assertIn("brand-deck", str(ctx.exception))

    def test_tampered_version_linkage_is_refused_at_load(self):
        designer = Actor.create("designer", "Freelance Designer")
        project = Project("brand-deck", "Brand Deck")
        project.add_collaborator(designer)
        project.upload(designer, b"v1", "2026-10-24T10:00:00Z", "v1")
        project.upload(designer, b"v2", "2026-10-24T11:00:00Z", "v2")
        users = {"designer": create_user("designer", "Freelance Designer", "pw")}

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            save_state(path, users, {"brand-deck": project})
            import json

            state = json.loads(path.read_text())
            state["projects"]["brand-deck"]["versions"][1][
                "parent_content_id"] = "sha256:0000"
            path.write_text(json.dumps(state))
            with self.assertRaises(ValueError):
                load_state(path)


if __name__ == "__main__":
    unittest.main()
