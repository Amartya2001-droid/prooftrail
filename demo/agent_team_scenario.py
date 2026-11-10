"""Demo scenario: the agent team works a disputed announcement.

v1: Amartya writes the original showcase announcement.
v2: Priya adds a paragraph, AI-assisted, and declares the tool.
v3: Priya rewrites most of the announcement with no declaration.
Then Trailboss runs the team twice: verify_project and
build_dispute_case. The reports print below, and the ledger still
verifies afterwards — the runs wrote signed events into it, they
did not rewrite history.

What to notice: the verdict stays "clean" because only high-severity
findings escalate it, and Sleuth's findings here are medium and low.
Sleuth flags the v3 rewrite and the sentences added with no
declaration on record — but absence of a declaration is not proof
of AI use, only that none was declared. Scribe's narrative is
deterministic template text built from the team's findings, not
LLM reasoning.

Run: python3 demo/agent_team_scenario.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prooftrail.agents import AgentReport, Orchestrator
from prooftrail.store import Actor, Project

V1 = ("Acadia Robotics Club announces its spring showcase. "
      "The showcase opens on 14 March at the Student Union Building. "
      "Admission is free for all students.")
V2 = (V1 + " Our robots will demonstrate line following, maze solving, "
      "and sumo wrestling. Bring your friends and meet the team "
      "behind the machines.")
V3 = ("Acadia Robotics Club invites everyone to its spring showcase. "
      "Join us on 14 March at the Student Union Building for an "
      "evening of live robot demos. Watch our robots follow lines, "
      "solve mazes, and battle in sumo wrestling. "
      "Admission is free, and everyone is welcome.")


def build_scenario() -> tuple[Project, list[AgentReport]]:
    """Build the disputed project and run the team on it twice."""
    writer = Actor.create("amartya", "Amartya")
    editor = Actor.create("priya", "Priya")
    project = Project("robotics-showcase", "Robotics Showcase Announcement")
    project.add_collaborator(writer)
    project.add_collaborator(editor)

    project.upload(writer, V1.encode(), "2026-10-24T10:00:00Z", "v1")
    project.upload(editor, V2.encode(), "2026-10-24T11:00:00Z", "v2")
    project.declare(editor, project.versions[1], "ChatGPT",
                    "Draft the demo paragraph", [],
                    "2026-10-24T11:05:00Z")
    project.upload(editor, V3.encode(), "2026-10-24T13:00:00Z", "v3")

    team = Orchestrator(project)
    reports = [
        team.run({"kind": "verify_project"}),
        team.run({"kind": "build_dispute_case"}),
    ]
    return project, reports


def _print_report(report: AgentReport) -> None:
    print(f"\n== {report.task_kind}: verdict {report.verdict} "
          f"(run {report.run_id}) ==")
    for agent_id, summary in report.summaries.items():
        print(f"  {agent_id}: {summary}")
    for finding in report.findings:
        print(f"  [{finding.severity}] {finding.agent_id}: "
              f"{finding.message}")


def main() -> None:
    project, reports = build_scenario()
    print("== Ledger valid after the runs:", project.verify() == [])
    print("== Runs recorded:", len(project.agent_runs))
    for report in reports:
        _print_report(report)
    print("\n== Honest notes ==")
    print("  Verdict stays 'clean': only high-severity findings "
          "escalate it.")
    print("  Sleuth's undeclared-addition finding is not proof of AI "
          "use — it only means none was declared for v3.")
    print("  Scribe's narrative is deterministic template text from "
          "the team's findings, not LLM reasoning.")


if __name__ == "__main__":
    main()
