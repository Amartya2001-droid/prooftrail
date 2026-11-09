"""Agent run log: runs recorded by the orchestrator are persisted
in the store and listable over the API — per project and across
all of the caller's projects — for collaborators only."""

import base64
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail.agents import Orchestrator
from prooftrail.server import ProofTrailApp, make_server


def call(conn, method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request(method, path, json.dumps(body) if body is not None else None,
                 headers)
    resp = conn.getresponse()
    data = json.loads(resp.read() or b"{}")
    return resp.status, data


class TestAgentRunsApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server, cls.app = make_server(
            "127.0.0.1", 0, str(Path(cls.tmp.name) / "state.json"))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)

    def _login(self, conn, username):
        call(conn, "POST", "/api/users",
             {"username": username, "name": username.title(),
              "password": "sunset-river-42"})
        _, login = call(conn, "POST", "/api/sessions",
                        {"username": username,
                         "password": "sunset-river-42"})
        return login["token"]

    def _project_with_run(self, conn, token, title="Brand deck"):
        _, proj = call(conn, "POST", "/api/projects",
                       {"title": title}, token=token)
        pid = proj["project_id"]
        call(conn, "POST", f"/api/projects/{pid}/uploads",
             {"content_base64": base64.b64encode(b"First draft.").decode(),
              "label": "v1"},
             token=token)
        report = Orchestrator(self.app.projects[pid]).run(
            {"kind": "verify_project"})
        return pid, report

    def test_runs_listed_per_project(self):
        conn = self.conn()
        token = self._login(conn, "owner-a")
        pid, report = self._project_with_run(conn, token)
        status, listed = call(
            conn, "GET", f"/api/projects/{pid}/agents/runs", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(listed["total"], 1)
        run = listed["runs"][0]
        self.assertEqual(run["run_id"], report.run_id)
        self.assertEqual(run["task_kind"], "verify_project")
        self.assertEqual(run["project_id"], pid)
        self.assertEqual(run["status"], "finished")
        self.assertEqual(run["findings_count"], len(report.findings))
        self.assertEqual(run["agents"],
                         ["verifier", "detective", "narrator"])
        self.assertTrue(run["started_at"])
        self.assertTrue(run["finished_at"])

    def test_runs_listed_across_projects(self):
        conn = self.conn()
        token = self._login(conn, "owner-b")
        pid1, _ = self._project_with_run(conn, token, "One")
        pid2, _ = self._project_with_run(conn, token, "Two")
        status, listed = call(conn, "GET", "/api/agents/runs", token=token)
        self.assertEqual(status, 200)
        ids = {r["project_id"] for r in listed["runs"]}
        self.assertIn(pid1, ids)
        self.assertIn(pid2, ids)

    def test_runs_require_auth(self):
        conn = self.conn()
        token = self._login(conn, "owner-c")
        pid, _ = self._project_with_run(conn, token)
        status, _ = call(conn, "GET", f"/api/projects/{pid}/agents/runs")
        self.assertEqual(status, 401)
        status, _ = call(conn, "GET", "/api/agents/runs")
        self.assertEqual(status, 401)

    def test_runs_are_collaborator_only(self):
        conn = self.conn()
        token = self._login(conn, "owner-d")
        pid, _ = self._project_with_run(conn, token)
        other = self._login(conn, "outsider-d")
        status, _ = call(conn, "GET",
                         f"/api/projects/{pid}/agents/runs", token=other)
        self.assertEqual(status, 403)
        # Across projects, an outsider sees only their own runs: none.
        status, listed = call(conn, "GET", "/api/agents/runs", token=other)
        self.assertEqual(status, 200)
        self.assertEqual(listed["total"], 0)

    def test_runs_paging(self):
        conn = self.conn()
        token = self._login(conn, "owner-e")
        pid, _ = self._project_with_run(conn, token)
        Orchestrator(self.app.projects[pid]).run(
            {"kind": "build_dispute_case"})
        status, page = call(
            conn, "GET", f"/api/projects/{pid}/agents/runs?limit=1",
            token=token)
        self.assertEqual(status, 200)
        self.assertEqual(page["total"], 2)
        self.assertEqual(len(page["runs"]), 1)
        first_id = page["runs"][0]["run_id"]
        status, page = call(
            conn, "GET",
            f"/api/projects/{pid}/agents/runs?limit=1&offset=1",
            token=token)
        self.assertEqual(len(page["runs"]), 1)
        self.assertNotEqual(page["runs"][0]["run_id"], first_id)

    def test_runs_survive_restart(self):
        conn = self.conn()
        token = self._login(conn, "owner-f")
        pid, report = self._project_with_run(conn, token)
        self.app._save()
        reloaded = ProofTrailApp(self.app.data_path)
        runs = reloaded.projects[pid].agent_runs
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].run_id, report.run_id)
        self.assertEqual(reloaded.projects[pid].verify(), [])


if __name__ == "__main__":
    unittest.main()
