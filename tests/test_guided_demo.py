"""Guided sample creation uses real signatures, persistence and authorization."""
import http.client
import json
import secrets
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from prooftrail.server import ApiError, ProofTrailApp, make_server
from prooftrail.demo_scenario import V1, V2, V3


class TestGuidedDemo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = str(Path(cls.tmp.name) / "state.json")
        cls.server, cls.app = make_server("127.0.0.1", 0, cls.path)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.password = secrets.token_urlsafe(24)
        cls.app.register("demo-owner", "Owner", cls.password)
        cls.token = cls.app.login("demo-owner", cls.password)["token"]
        cls.app.register("other-owner", "Other", cls.password)
        cls.other_token = cls.app.login("other-owner", cls.password)["token"]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def call(self, body, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=60)
        try:
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            conn.request("POST", "/api/demo/projects", json.dumps(body), headers)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        finally:
            conn.close()

    def test_http_requires_auth_and_valid_request_id(self):
        before = len(self.app.projects)
        self.assertEqual(self.call({"request_id": "a" * 32})[0], 401)
        for value in ("", "x" * 32, None, 42):
            self.assertEqual(self.call({"request_id": value}, self.token)[0], 400)
        self.assertEqual(self.call({}, self.token)[0], 400)
        self.assertEqual(len(self.app.projects), before)

    def test_signed_sample_is_private_and_retry_does_not_duplicate(self):
        nonce = secrets.token_hex(16)
        status, sample = self.call({"request_id": nonce}, self.token)
        self.assertEqual(status, 201)
        self.assertTrue(sample["created"])
        self.assertTrue(sample["synthetic"])
        project = self.app.projects[sample["project_id"]]
        self.assertEqual([project.read(v).decode() for v in project.versions], [V1, V2, V3])
        self.assertEqual(project.verify(), [])
        self.assertNotEqual(project.versions[0].actor_id, project.versions[1].actor_id)
        self.assertEqual(len(project.declarations()), 1)
        self.assertEqual(set(self.app.users), {"demo-owner", "other-owner"})
        for actor in project.collaborators.values():
            if actor.actor_id != "demo-owner":
                self.assertIn("synthetic", actor.name)
                self.assertEqual(actor.secret_key, b"")
        event_count = len(project.ledger.events)
        _, repeated = self.call({"request_id": nonce}, self.token)
        self.assertFalse(repeated["created"])
        self.assertEqual(repeated["project_id"], sample["project_id"])
        self.assertEqual(len(project.ledger.events), event_count)
        with self.assertRaises(ApiError) as error:
            self.app.agent_runs_for_project(self.other_token, sample["project_id"])
        self.assertIn(error.exception.status, (403, 404))
        other = self.app.create_demo(self.other_token, nonce)
        self.assertNotEqual(other["project_id"], sample["project_id"])

    def test_retry_after_save_failure_keeps_same_sample(self):
        nonce = secrets.token_hex(16)
        before = set(self.app.projects)
        with patch.object(self.app, "_save", side_effect=OSError("temporary save failure")):
            with self.assertRaises(OSError):
                self.app.create_demo(self.token, nonce)
        created = set(self.app.projects) - before
        self.assertEqual(len(created), 1)
        result = self.app.create_demo(self.token, nonce)
        self.assertEqual(created, {result["project_id"]})
        self.assertFalse(result["created"])
        self.assertEqual(self.app.projects[result["project_id"]].verify(), [])

    def test_restart_preserves_sample_and_idempotency(self):
        nonce = secrets.token_hex(16)
        sample = self.app.create_demo(self.token, nonce)
        loaded = ProofTrailApp(self.path)
        token = loaded.login("demo-owner", self.password)["token"]
        repeated = loaded.create_demo(token, nonce)
        self.assertEqual(repeated["project_id"], sample["project_id"])
        self.assertFalse(repeated["created"])
        project = loaded.projects[sample["project_id"]]
        self.assertEqual(project.verify(), [])
        self.assertEqual(len(project.versions), 3)
