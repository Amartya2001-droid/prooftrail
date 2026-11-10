"""Agent-team demo scenario: the scripted dispute runs the team
twice and the reports show what each specialist actually found."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "demo" / "agent_team_scenario.py"


def load_demo():
    spec = importlib.util.spec_from_file_location(
        "agent_team_scenario", DEMO)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestAgentTeamDemo(unittest.TestCase):
    def test_both_runs_finish_and_ledger_still_verifies(self):
        demo = load_demo()
        project, reports = demo.build_scenario()
        self.assertEqual(len(reports), 2)
        self.assertEqual([r.task_kind for r in reports],
                         ["verify_project", "build_dispute_case"])
        for report in reports:
            self.assertEqual(report.verdict, "clean")
        self.assertEqual(len(project.agent_runs), 2)
        self.assertEqual(project.verify(), [])

    def test_sleuth_flags_the_undeclared_rewrite(self):
        demo = load_demo()
        _, reports = demo.build_scenario()
        findings = reports[0].findings
        rewrite = [f for f in findings
                   if f.agent_id == "detective"
                   and "rewrote most of the document" in f.message]
        self.assertEqual(len(rewrite), 1)
        self.assertEqual(rewrite[0].severity, "medium")
        undeclared = [f for f in findings
                      if f.agent_id == "detective"
                      and "no AI-use declaration" in f.message]
        self.assertEqual(len(undeclared), 1)
        self.assertEqual(undeclared[0].severity, "low")

    def test_dispute_case_maps_the_declared_ai_help(self):
        demo = load_demo()
        _, reports = demo.build_scenario()
        report = reports[1]
        self.assertIn("cartographer", report.summaries)
        mapped = [f for f in report.findings
                  if f.agent_id == "cartographer"
                  and "Version 'v2'" in f.message]
        self.assertEqual(len(mapped), 1)
        self.assertIn("2 ai-assisted", mapped[0].message)
        self.assertIn("ChatGPT", mapped[0].message)

    def test_scribe_narrates_the_rewrite(self):
        demo = load_demo()
        _, reports = demo.build_scenario()
        narrative = [f for f in reports[0].findings
                     if f.agent_id == "narrator"]
        self.assertEqual(len(narrative), 1)
        self.assertIn("rewrote most of the document",
                      narrative[0].message)
        self.assertIn("cannot prove how", narrative[0].message)


class TestAgentTeamReadme(unittest.TestCase):
    def test_readme_documents_the_agent_team(self):
        text = (ROOT / "README.md").read_text()
        self.assertIn("## Agent team", text)
        self.assertIn("Trailboss", text)
        self.assertIn("Verity", text)
        self.assertIn("Sleuth", text)
        self.assertIn("Mapper", text)
        self.assertIn("Scribe", text)
        self.assertIn("demo/agent_team_scenario.py", text)
        self.assertIn("/agents/run", text)
        self.assertIn("deterministic template text", text)
        self.assertIn("proof of AI use", text)


if __name__ == "__main__":
    unittest.main()
