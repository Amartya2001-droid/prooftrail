"""Agent registry: five named roles, each with a stable id, a display
name, a one-line role description and a list of capabilities.

Orchestrator: dispatching a task to the right specialists and merging
their findings into one report, with Verity re-verifying the ledger
for real and the other specialists honest about not being built yet."""

import tempfile
import unittest
from pathlib import Path

from prooftrail.agents import (
    Orchestrator,
    get_role,
    list_roles,
)
from prooftrail.persistence import load_state, save_state
from prooftrail.store import Actor, AgentRun, Project


def _project_with_version() -> Project:
    project = Project("proj-1", "Brand deck")
    actor = Actor.create("alice", "Alice")
    project.add_collaborator(actor)
    project.upload(actor, b"First draft. Second sentence.",
                   "2026-11-09T00:00:00+00:00", label="v1")
    return project


class TestAgentRegistry(unittest.TestCase):
    def test_five_roles_registered(self):
        self.assertEqual(len(list_roles()), 5)

    def test_role_ids_are_stable_and_unique(self):
        ids = [role.agent_id for role in list_roles()]
        self.assertEqual(ids, ["orchestrator", "verifier", "detective",
                               "cartographer", "narrator"])
        self.assertEqual(len(set(ids)), len(ids))

    def test_lookup_by_id(self):
        role = get_role("verifier")
        self.assertEqual(role.name, "Verity")
        self.assertIn("hash chains", role.role)
        self.assertIn("verify signatures", role.capabilities)

    def test_each_role_has_name_description_and_capabilities(self):
        for role in list_roles():
            self.assertTrue(role.name)
            self.assertTrue(role.role)
            self.assertTrue(role.capabilities)

    def test_display_names(self):
        names = {role.agent_id: role.name for role in list_roles()}
        self.assertEqual(names, {
            "orchestrator": "Trailboss",
            "verifier": "Verity",
            "detective": "Sleuth",
            "cartographer": "Mapper",
            "narrator": "Scribe",
        })

    def test_unknown_id_raises(self):
        with self.assertRaises(KeyError):
            get_role("no-such-agent")

    def test_list_returns_a_copy(self):
        roles = list_roles()
        roles.clear()
        self.assertEqual(len(list_roles()), 5)


class TestOrchestrator(unittest.TestCase):
    def test_verify_project_on_clean_project(self):
        project = _project_with_version()
        report = Orchestrator(project).run(
            {"kind": "verify_project", "project_id": "proj-1"})
        # Stubs are honest, so a clean ledger still reads incomplete.
        self.assertEqual(report.verdict, "incomplete")
        self.assertEqual(report.task_kind, "verify_project")
        self.assertEqual(report.project_id, "proj-1")
        self.assertTrue(report.run_id.startswith("run-"))
        self.assertEqual(set(report.summaries),
                         {"verifier", "detective", "narrator"})
        verity = [f for f in report.findings
                  if f.agent_id == "verifier"]
        # Verity reports per version plus one chain finding.
        self.assertEqual(len(verity), 2)
        chain, version = verity
        self.assertEqual(chain.status, "complete")
        self.assertEqual(chain.severity, "info")
        self.assertIn("Ledger chain verified", chain.message)
        self.assertEqual(version.status, "complete")
        self.assertEqual(version.severity, "info")
        self.assertIn("'v1'", version.message)
        self.assertIn("content hash matches", version.message)

    def test_verify_project_finds_tampered_ledger(self):
        project = _project_with_version()
        # Rewrite history: change the payload of the upload event.
        project.ledger.events[0]["payload"]["label"] = "forged"
        report = Orchestrator(project).run({"kind": "verify_project"})
        self.assertEqual(report.verdict, "issues_found")
        bad = [f for f in report.findings
               if f.agent_id == "verifier" and f.severity == "high"]
        self.assertTrue(bad)

    def test_build_dispute_case_uses_all_specialists(self):
        project = _project_with_version()
        report = Orchestrator(project).run(
            {"kind": "build_dispute_case", "project_id": "proj-1"})
        self.assertEqual(set(report.summaries),
                         {"verifier", "detective", "cartographer",
                          "narrator"})
        self.assertEqual(report.verdict, "incomplete")

    def test_stub_findings_are_marked_not_implemented(self):
        project = _project_with_version()
        report = Orchestrator(project).run({"kind": "verify_project"})
        stubs = [f for f in report.findings
                 if f.agent_id in ("detective", "narrator")]
        self.assertTrue(stubs)
        for finding in stubs:
            self.assertEqual(finding.status, "not_implemented")
            self.assertIn("not yet implemented", finding.message)

    def test_unknown_kind_raises(self):
        project = _project_with_version()
        with self.assertRaises(ValueError):
            Orchestrator(project).run({"kind": "audit_everything"})

    def test_project_id_mismatch_raises(self):
        project = _project_with_version()
        with self.assertRaises(ValueError):
            Orchestrator(project).run(
                {"kind": "verify_project", "project_id": "other"})

    def test_run_ids_are_unique(self):
        project = _project_with_version()
        orch = Orchestrator(project)
        first = orch.run({"kind": "verify_project"})
        second = orch.run({"kind": "verify_project"})
        self.assertNotEqual(first.run_id, second.run_id)


class TestAgentLedgerEvents(unittest.TestCase):
    def _run(self, project):
        return Orchestrator(project).run({"kind": "verify_project"})

    def _agent_events(self, project):
        return [e for e in project.ledger.events
                if e["type"].startswith("agent_")]

    def test_run_records_signed_events_on_ledger(self):
        project = _project_with_version()
        report = self._run(project)
        events = self._agent_events(project)
        kinds = [e["type"] for e in events]
        self.assertEqual(kinds[0], "agent_run_started")
        self.assertEqual(kinds[-1], "agent_run_finished")
        self.assertEqual(kinds.count("agent_finding"),
                         len(report.findings))
        # Every agent event is signed by its own namespaced actor.
        actors = {e["actor"] for e in events}
        self.assertIn("agent:orchestrator", actors)
        self.assertIn("agent:verifier", actors)
        # The run is still fully verifiable after recording it.
        self.assertEqual(project.verify(), [])

    def test_started_and_finished_carry_the_run_id(self):
        project = _project_with_version()
        report = self._run(project)
        events = self._agent_events(project)
        started = next(e for e in events
                       if e["type"] == "agent_run_started")
        finished = next(e for e in events
                        if e["type"] == "agent_run_finished")
        self.assertEqual(started["payload"]["run_id"], report.run_id)
        self.assertEqual(finished["payload"]["run_id"], report.run_id)
        self.assertEqual(finished["payload"]["verdict"], report.verdict)
        self.assertEqual(finished["payload"]["findings_count"],
                         len(report.findings))

    def test_tampered_agent_finding_fails_verification(self):
        project = _project_with_version()
        self._run(project)
        finding = next(e for e in project.ledger.events
                       if e["type"] == "agent_finding")
        finding["payload"]["message"] = "all clear, nothing to see here"
        self.assertNotEqual(project.verify(), [])

    def test_tampered_run_finished_fails_verification(self):
        project = _project_with_version()
        self._run(project)
        finished = next(e for e in project.ledger.events
                        if e["type"] == "agent_run_finished")
        finished["payload"]["verdict"] = "clean"
        self.assertNotEqual(project.verify(), [])

    def test_agent_actors_are_registered_on_the_ledger(self):
        project = _project_with_version()
        self._run(project)
        self.assertIn("agent:verifier",
                      project.ledger._public_keys)
        self.assertIn("agent:orchestrator",
                      project.ledger._public_keys)

    def test_agent_events_survive_save_and_load(self):
        project = _project_with_version()
        self._run(project)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            save_state(path, {}, {"proj-1": project})
            _, loaded = load_state(path)
            reloaded = loaded["proj-1"]
            self.assertEqual(reloaded.verify(), [])
            kinds = [e["type"] for e in reloaded.ledger.events]
            self.assertIn("agent_run_started", kinds)
            self.assertIn("agent_finding", kinds)
            self.assertIn("agent_run_finished", kinds)


class TestAgentRunLog(unittest.TestCase):
    def test_run_record_round_trips(self):
        run = AgentRun(
            run_id="run-abc", task_kind="verify_project",
            project_id="proj-1", agents=["verifier"],
            status="finished", findings_count=2,
            started_at="2026-11-09T00:00:00+00:00",
            finished_at="2026-11-09T00:00:01+00:00")
        restored = AgentRun.from_dict(run.to_dict())
        self.assertEqual(restored, run)

    def test_orchestrator_records_the_run(self):
        project = _project_with_version()
        report = Orchestrator(project).run({"kind": "verify_project"})
        self.assertEqual(len(project.agent_runs), 1)
        run = project.agent_runs[0]
        self.assertEqual(run.run_id, report.run_id)
        self.assertEqual(run.task_kind, "verify_project")
        self.assertEqual(run.project_id, "proj-1")
        self.assertEqual(run.status, "finished")
        self.assertEqual(run.findings_count, len(report.findings))
        self.assertEqual(run.agents,
                         ["verifier", "detective", "narrator"])
        self.assertTrue(run.started_at)
        self.assertTrue(run.finished_at)

    def test_run_log_survives_save_and_load(self):
        project = _project_with_version()
        report = Orchestrator(project).run({"kind": "verify_project"})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            save_state(path, {}, {"proj-1": project})
            _, loaded = load_state(path)
            runs = loaded["proj-1"].agent_runs
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0].run_id, report.run_id)


if __name__ == "__main__":
    unittest.main()
