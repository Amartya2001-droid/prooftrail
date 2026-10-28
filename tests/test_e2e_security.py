"""End-to-end security tests against a live ProofTrail server.

Each test attacks the real HTTP surface: authentication, authorisation,
input validation, brute-force defence, session lifecycle, timestamp
trust, and on-disk state safety. These are the tests that earn the word
"waterproof" — they fail if any hardening regresses.
"""

import base64
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.auth import SessionStore
from prooftrail.persistence import load_state
from prooftrail.server import MAX_BODY_BYTES, make_server


def call(conn, method, path, body=None, token=None, headers=None):
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    conn.request(method, path, json.dumps(body) if body is not None else None,
                 hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    try:
        data = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        data = {}
    return resp.status, data


class SecurityTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.state_path = str(Path(cls.tmp.name) / "state.json")
        cls.server, _ = make_server("127.0.0.1", 0, cls.state_path)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                               timeout=30)

    def tearDown(self):
        self.conn.close()

    def register_login(self, username):
        status, _ = call(self.conn, "POST", "/api/users",
                         {"username": username, "name": username,
                          "password": "password123"})
        self.assertIn(status, (201, 409))
        status, login = call(self.conn, "POST", "/api/sessions",
                             {"username": username, "password": "password123"})
        self.assertEqual(status, 200)
        return login["token"]

    def make_project(self, token, title="Project"):
        status, proj = call(self.conn, "POST", "/api/projects",
                            {"title": title}, token=token)
        self.assertEqual(status, 201)
        return proj["project_id"]

    # -- authentication & authorisation ------------------------------------
    def test_unauthenticated_and_bogus_tokens_rejected(self):
        token = self.register_login("alice-sec")
        pid = self.make_project(token)
        for path in (f"/api/projects/{pid}/versions",
                     f"/api/projects/{pid}/verify"):
            status, _ = call(self.conn, "GET", path)
            self.assertEqual(status, 401, path)
            status, _ = call(self.conn, "GET", path, token="bogus-token")
            self.assertEqual(status, 401, path)
        status, _ = call(self.conn, "POST", "/api/projects",
                         {"title": "Nope"})
        self.assertEqual(status, 401)

    def test_non_collaborator_gets_403_not_data(self):
        owner = self.register_login("owner-sec")
        outsider = self.register_login("outsider-sec")
        pid = self.make_project(owner)
        status, body = call(self.conn, "GET", f"/api/projects/{pid}/versions",
                            token=outsider)
        self.assertEqual(status, 403)
        self.assertNotIn("versions", body)

    def test_login_does_not_enumerate_users(self):
        status, body = call(self.conn, "POST", "/api/sessions",
                            {"username": "nobody-here",
                             "password": "whatever123"})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "invalid credentials")

    # -- brute force & sessions --------------------------------------------
    def test_login_lockout_after_repeated_failures(self):
        self.register_login("lockout-user")
        for _ in range(5):
            status, _ = call(self.conn, "POST", "/api/sessions",
                             {"username": "lockout-user",
                              "password": "wrongpass"})
            self.assertEqual(status, 401)
        # Even the correct password is refused while locked out.
        status, body = call(self.conn, "POST", "/api/sessions",
                            {"username": "lockout-user",
                             "password": "password123"})
        self.assertEqual(status, 429)

    def test_logout_revokes_token(self):
        token = self.register_login("logout-user")
        pid = self.make_project(token)
        status, _ = call(self.conn, "POST", "/api/sessions/revoke",
                         token=token)
        self.assertEqual(status, 200)
        status, _ = call(self.conn, "GET", f"/api/projects/{pid}/versions",
                         token=token)
        self.assertEqual(status, 401)

    def test_expired_sessions_rejected(self):
        clock = [1000.0]
        store = SessionStore(ttl_seconds=60, time_fn=lambda: clock[0])
        token = store.create("someone")
        self.assertEqual(store.lookup(token), "someone")
        clock[0] = 2000.0
        self.assertIsNone(store.lookup(token))

    # -- input validation ----------------------------------------------------
    def test_malformed_json_bad_base64_and_wrong_content_type(self):
        token = self.register_login("input-user")
        pid = self.make_project(token)
        self.conn.request("POST", f"/api/projects/{pid}/uploads",
                          "{not json",
                          {"Content-Type": "application/json",
                           "Authorization": f"Bearer {token}"})
        resp = self.conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 400)
        status, _ = call(self.conn, "POST", f"/api/projects/{pid}/uploads",
                         {"content_base64": "!!!not-base64!!!"},
                         token=token)
        self.assertEqual(status, 400)
        status, _ = call(self.conn, "POST", f"/api/projects/{pid}/uploads",
                         {"content_base64": "aGk="}, token=token,
                         headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_oversized_body_rejected_on_headers(self):
        token = self.register_login("big-user")
        pid = self.make_project(token)
        # Send headers declaring a body over the cap, but no body: the
        # server must answer 413 without waiting for the bytes.
        self.conn.putrequest("POST", f"/api/projects/{pid}/uploads")
        self.conn.putheader("Content-Type", "application/json")
        self.conn.putheader("Authorization", f"Bearer {token}")
        self.conn.putheader("Content-Length", str(MAX_BODY_BYTES + 1))
        self.conn.endheaders()
        resp = self.conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 413)

    # -- provenance trust ----------------------------------------------------
    def test_client_supplied_timestamp_is_ignored(self):
        token = self.register_login("time-user")
        pid = self.make_project(token)
        status, version = call(
            self.conn, "POST", f"/api/projects/{pid}/uploads",
            {"content_base64": base64.b64encode(b"hello").decode(),
             "label": "v1", "timestamp": "1999-01-01T00:00:00Z"},
            token=token)
        self.assertEqual(status, 201)
        self.assertFalse(version["timestamp"].startswith("1999"))

    def test_password_policy_enforced(self):
        status, _ = call(self.conn, "POST", "/api/users",
                         {"username": "short-pw", "name": "Short",
                          "password": "abc"})
        self.assertEqual(status, 400)

    # -- on-disk state ---------------------------------------------------------
    def test_state_file_has_no_secrets_and_tamper_is_caught(self):
        token = self.register_login("disk-user")
        pid = self.make_project(token)
        call(self.conn, "POST", f"/api/projects/{pid}/uploads",
             {"content_base64": base64.b64encode(b"secret work").decode(),
              "label": "v1"}, token=token)
        raw = Path(self.state_path).read_text()
        self.assertNotIn("password123", raw)
        self.assertNotIn("secret_key", raw)
        if os.name == "posix":
            self.assertEqual(oct(os.stat(self.state_path).st_mode & 0o777),
                             "0o600")
        state = json.loads(raw)
        project = state["projects"][pid]
        self.assertTrue(project["events"])
        project["events"][0]["content_id"] = "sha256:" + "0" * 64
        tampered = Path(self.tmp.name) / "tampered.json"
        tampered.write_text(json.dumps(state))
        # A tampered state file is refused at load time, not served and
        # caught later: the guardrail is the refusal itself.
        with self.assertRaises(ValueError) as ctx:
            load_state(tampered)
        self.assertIn(pid, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
