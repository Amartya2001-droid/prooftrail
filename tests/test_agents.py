"""Agent registry: five named roles, each with a stable id, a display
name, a one-line role description and a list of capabilities.

Orchestrator: dispatching a task to the right specialists and merging
their findings into one report, with Verity re-verifying the ledger
for real and the other specialists honest about not being built yet."""

import unittest

from prooftrail.agents import (
    Orchestrator,
    get_role,
    list_roles,
)
from prooftrail.store import Actor, Project


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
        self.assertEqual(len(verity), 1)
        self.assertEqual(verity[0].status, "complete")
        self.assertEqual(verity[0].severity, "info")
        self.assertIn("Ledger verified", verity[0].message)

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


if __name__ == "__main__":
    unittest.main()
