"""Week-1 improvement tests, each against its own project and state."""

import base64
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.server import make_server


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


class ImprovementTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server, _ = make_server("127.0.0.1", 0,
                                    str(Path(cls.tmp.name) / "state.json"))
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
        self._n = getattr(self, "_n", 0) + 1
        ImprovementTestCase._n = self._n

    def tearDown(self):
        self.conn.close()

    def user(self, name):
        status, _ = call(self.conn, "POST", "/api/users",
                         {"username": name, "name": name,
                          "password": "sunset-river-42"})
        self.assertIn(status, (201, 409))
        status, login = call(self.conn, "POST", "/api/sessions",
                             {"username": name, "password": "sunset-river-42"})
        self.assertEqual(status, 200)
        return login["token"]

    def project(self, token, title="Project"):
        status, proj = call(self.conn, "POST", "/api/projects",
                            {"title": title}, token=token)
        self.assertEqual(status, 201)
        return proj["project_id"]

    def upload(self, token, pid, text, label="v1", **extra):
        body = {"content_base64": base64.b64encode(text.encode()).decode(),
                "label": label}
        body.update(extra)
        status, version = call(self.conn, "POST",
                               f"/api/projects/{pid}/uploads",
                               body, token=token)
        self.assertEqual(status, 201)
        return version


class TestListProjects(ImprovementTestCase):
    def test_lists_only_own_projects(self):
        alice = self.user("alice-list")
        bob = self.user("bob-list")
        pid_a = self.project(alice, "Alice Project")
        self.project(bob, "Bob Project")
        status, body = call(self.conn, "GET", "/api/projects", token=alice)
        self.assertEqual(status, 200)
        ids = [p["project_id"] for p in body["projects"]]
        self.assertIn(pid_a, ids)
        self.assertEqual(len(ids), 1)
        self.assertEqual(body["projects"][0]["versions"], 0)




class TestVersionMetadata(ImprovementTestCase):
    def test_filename_type_and_size_round_trip(self):
        alice = self.user("alice-meta")
        pid = self.project(alice, "Meta Project")
        text = "hello metadata"
        version = self.upload(alice, pid, text, label="draft",
                              filename="brief.txt", content_type="text/plain")
        self.assertEqual(version["filename"], "brief.txt")
        self.assertEqual(version["content_type"], "text/plain")
        self.assertEqual(version["size"], len(text))
        status, body = call(self.conn, "GET",
                            f"/api/projects/{pid}/versions", token=alice)
        self.assertEqual(status, 200)
        self.assertEqual(body["versions"][0]["filename"], "brief.txt")
        self.assertEqual(body["versions"][0]["size"], len(text))


class TestIdempotentUpload(ImprovementTestCase):
    def test_same_bytes_twice_is_one_version(self):
        alice = self.user("alice-dup")
        pid = self.project(alice, "Dup Project")
        first = self.upload(alice, pid, "same bytes", label="v1")
        self.assertFalse(first["duplicate"])
        second = self.upload(alice, pid, "same bytes", label="v1 again")
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["content_id"], first["content_id"])
        status, body = call(self.conn, "GET",
                            f"/api/projects/{pid}/versions", token=alice)
        self.assertEqual(len(body["versions"]), 1)
        status, verify = call(self.conn, "GET",
                              f"/api/projects/{pid}/verify", token=alice)
        self.assertEqual(len(verify["versions"]), 1)
        self.assertEqual(verify["events"], 1)


class TestEventsEndpoint(ImprovementTestCase):
    def test_events_paginate_newest_first(self):
        alice = self.user("alice-events")
        pid = self.project(alice, "Events Project")
        v1 = self.upload(alice, pid, "first", label="v1")
        self.upload(alice, pid, "second", label="v2")
        call(self.conn, "POST", f"/api/projects/{pid}/approvals",
             {"content_id": v1["content_id"]}, token=alice)
        status, page1 = call(self.conn, "GET",
                             f"/api/projects/{pid}/events?limit=2",
                             token=alice)
        self.assertEqual(status, 200)
        self.assertEqual(page1["total"], 3)
        self.assertEqual(len(page1["events"]), 2)
        self.assertEqual(page1["events"][0]["type"], "approval")
        status, page2 = call(self.conn, "GET",
                             f"/api/projects/{pid}/events?limit=2&offset=2",
                             token=alice)
        self.assertEqual(len(page2["events"]), 1)
        self.assertEqual(page2["events"][0]["type"], "upload")
        status, _ = call(self.conn, "GET",
                         f"/api/projects/{pid}/events?limit=500",
                         token=alice)
        self.assertEqual(status, 400)


class TestHealthAndDocs(ImprovementTestCase):
    def test_health_needs_no_auth(self):
        status, body = call(self.conn, "GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["version"])

    def test_openapi_lists_project_routes(self):
        status, body = call(self.conn, "GET", "/api/openapi.json")
        self.assertEqual(status, 200)
        self.assertIn("/api/projects/{id}/events", body["paths"])
        self.assertIn("/api/projects/{id}/verify", body["paths"])


class TestExportEndpoint(ImprovementTestCase):
    def test_export_bundle_verifies(self):
        from prooftrail.verification import verify_evidence_bundle
        alice = self.user("alice-export")
        pid = self.project(alice, "Export Project")
        self.upload(alice, pid, "export me", label="v1")
        status, bundle = call(
            self.conn, "GET",
            f"/api/projects/{pid}/export?claim=authorship%20dispute",
            token=alice)
        self.assertEqual(status, 200)
        self.assertEqual(bundle["claim"], "authorship dispute")
        self.assertEqual(verify_evidence_bundle(bundle), [])
        # A stranger must not be able to export someone else's project.
        bob = self.user("bob-export")
        status, _ = call(self.conn, "GET", f"/api/projects/{pid}/export",
                         token=bob)
        self.assertEqual(status, 403)




class TestExportClaimLimit(ImprovementTestCase):
    def test_export_claim_length_limited(self):
        alice = self.user("alice-claim")
        pid = self.project(alice, "Claim Project")
        self.upload(alice, pid, "claim me", label="v1")
        status, _ = call(
            self.conn, "GET",
            f"/api/projects/{pid}/export?claim={'x' * 501}",
            token=alice)
        self.assertEqual(status, 400)
        status, bundle = call(
            self.conn, "GET",
            f"/api/projects/{pid}/export?claim={'x' * 500}",
            token=alice)
        self.assertEqual(status, 200)
        self.assertEqual(bundle["claim"], "x" * 500)


class TestValidation(ImprovementTestCase):
    def test_bad_username_and_title_and_filename_rejected(self):
        status, _ = call(self.conn, "POST", "/api/users",
                         {"username": "bad name!", "name": "Bad",
                          "password": "sunset-river-42"})
        self.assertEqual(status, 400)
        alice = self.user("alice-valid")
        status, _ = call(self.conn, "POST", "/api/projects",
                         {"title": "   "}, token=alice)
        self.assertEqual(status, 400)
        pid = self.project(alice, "Valid Project")
        status, _ = call(self.conn, "POST", f"/api/projects/{pid}/uploads",
                         {"content_base64": "aGk=",
                          "filename": "../escape.txt"}, token=alice)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
