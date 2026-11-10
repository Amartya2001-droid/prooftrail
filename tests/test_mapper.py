"""Mapper (cartographer): the real contribution map.

Who wrote what, per version and per actor: human vs AI-assisted vs
imported, from declarations plus version metadata, using the same
contribution map the project already publishes. A sentence counts
toward the version where it was first seen; carried-over sentences
keep their original version's attribution."""

import unittest

from prooftrail.agents import Orchestrator
from prooftrail.store import Actor, Project


def _project():
    project = Project("proj-1", "Brand deck")
    alice = Actor.create("alice", "Alice")
    bob = Actor.create("bob", "Bob")
    project.add_collaborator(alice)
    project.add_collaborator(bob)
    return project, {"alice": alice, "bob": bob}


def _upload(project, actors, actor_id, text, label, timestamp):
    return project.upload(actors[actor_id], text.encode(), timestamp,
                          label=label)


def _mapper_findings(project):
    report = Orchestrator(project).run({"kind": "build_dispute_case"})
    findings = [f for f in report.findings
                if f.agent_id == "cartographer"]
    return findings, report


class TestMapperBasic(unittest.TestCase):
    def test_single_version_all_human(self):
        project, actors = _project()
        _upload(project, actors, "alice", "First draft. Second sentence.",
                "v1", "2026-11-01T00:00:00+00:00")
        findings, report = _mapper_findings(project)
        self.assertEqual(len(findings), 2)  # coverage + v1
        coverage, version = findings
        self.assertIn("100% human", coverage.message)
        self.assertIn("0% AI-assisted", coverage.message)
        self.assertIn("absence of a declaration is not proof",
                      coverage.message)
        self.assertIn("'v1' by alice", version.message)
        self.assertIn("2 sentence(s) first seen here — 2 human",
                      version.message)
        self.assertIn("Mapped 1 version(s): 100% human",
                      report.summaries["cartographer"])

    def test_empty_project_has_nothing_to_map(self):
        project = Project("proj-empty", "Empty")
        actor = Actor.create("alice", "Alice")
        project.add_collaborator(actor)
        findings, report = _mapper_findings(project)
        self.assertEqual(len(findings), 1)
        self.assertIn("No versions to map yet", findings[0].message)
        self.assertIn("No versions to map",
                      report.summaries["cartographer"])


class TestMapperDeclarations(unittest.TestCase):
    def test_declared_version_is_ai_assisted(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        v2 = _upload(project, actors, "alice",
                     "One. Two. Three. Four. Five. Six.", "v2",
                     "2026-11-02T00:00:00+00:00")
        project.declare(actors["alice"], v2, "ChatGPT",
                        timestamp="2026-11-02T00:00:00+00:00")
        findings, report = _mapper_findings(project)
        coverage = findings[0]
        # 8 segments: 4 human (v1's 2 plus 2 carried) and 4 AI-assisted.
        self.assertIn("50% human", coverage.message)
        self.assertIn("50% AI-assisted", coverage.message)
        by_version = findings[1:]
        v1 = next(f for f in by_version if "'v1'" in f.message)
        v2f = next(f for f in findings[1:] if "'v2'" in f.message)
        self.assertIn("2 sentence(s) first seen here — 2 human",
                      v1.message)
        self.assertIn("4 sentence(s) first seen here — 4 ai-assisted",
                      v2f.message)
        self.assertIn("declared tool: ChatGPT", v2f.message)
        self.assertIn("Mapped 2 version(s): 50% human, 50% AI-assisted",
                      report.summaries["cartographer"])

    def test_partial_declaration_splits_the_version(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        v2 = _upload(project, actors, "alice",
                     "One. Two. Three. Four. Five. Six. Seven. Eight.",
                     "v2", "2026-11-02T00:00:00+00:00")
        project.declare(actors["alice"], v2, "ChatGPT",
                        sentence_indices=[2, 3],
                        timestamp="2026-11-02T00:00:00+00:00")
        findings, _ = _mapper_findings(project)
        v2f = next(f for f in findings[1:] if "'v2'" in f.message)
        # First seen in v2: 6 sentences — 2 AI-assisted, 4 human.
        self.assertIn("6 sentence(s) first seen here", v2f.message)
        self.assertIn("2 ai-assisted", v2f.message)
        self.assertIn("4 human", v2f.message)
        coverage = findings[0]
        # 10 segments: 8 human (v1's 2, 2 carried, 4 undeclared adds)
        # and 2 AI-assisted.
        self.assertIn("80% human", coverage.message)
        self.assertIn("20% AI-assisted", coverage.message)

    def test_two_actors_are_attributed_per_version(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two. Three.", "v1",
                "2026-11-01T00:00:00+00:00")
        _upload(project, actors, "bob", "One. Two. Three. Four.", "v2",
                "2026-11-02T00:00:00+00:00")
        findings, _ = _mapper_findings(project)
        v1 = next(f for f in findings[1:] if "'v1'" in f.message)
        v2f = next(f for f in findings[1:] if "'v2'" in f.message)
        self.assertIn("'v1' by alice", v1.message)
        self.assertIn("'v2' by bob", v2f.message)
        self.assertIn("1 sentence(s) first seen here — 1 human",
                      v2f.message)

    def test_imported_share_is_zero_with_honest_note(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        findings, _ = _mapper_findings(project)
        coverage = findings[0]
        self.assertIn("0% imported", coverage.message)
        self.assertIn("a gap in the record, not proof none exist",
                      coverage.message)


if __name__ == "__main__":
    unittest.main()
