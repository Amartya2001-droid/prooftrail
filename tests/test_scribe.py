"""Scribe (narrator): the real plain-language proof narrative.

Scribe runs last, so it narrates what the team found: Verity's
verification, the change history, who wrote what, and anything
Sleuth flagged — in words a non-technical reader can follow, with
the honest caveats about what the record cannot prove."""

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


def _narrative(project, kind="verify_project"):
    report = Orchestrator(project).run({"kind": kind})
    findings = [f for f in report.findings if f.agent_id == "narrator"]
    assert len(findings) == 1
    return findings[0].message, report


class TestScribeClean(unittest.TestCase):
    def test_narrative_covers_the_whole_story(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        v2 = _upload(project, actors, "alice",
                     "One. Two. Three. Four. Five. Six.", "v2",
                     "2026-11-02T00:00:00+00:00")
        project.declare(actors["alice"], v2, "ChatGPT",
                        timestamp="2026-11-02T00:00:00+00:00")
        narrative, report = _narrative(project)
        self.assertIn("Brand deck", narrative)
        self.assertIn("2 version(s)", narrative)
        self.assertIn("Alice", narrative)
        self.assertIn("1 November 2026", narrative)
        self.assertIn("The record checks out", narrative)
        self.assertIn("expanded the document", narrative)
        self.assertIn("50% of the text is human-written", narrative)
        self.assertIn("50% was written with AI help", narrative)
        self.assertIn("ChatGPT", narrative)
        self.assertIn("Nothing unusual stood out", narrative)
        self.assertIn("cannot prove how any sentence was first written",
                      narrative)
        self.assertEqual(report.verdict, "clean")

    def test_single_version_has_no_change_history(self):
        project, actors = _project()
        _upload(project, actors, "alice", "First draft. Second sentence.",
                "v1", "2026-11-01T00:00:00+00:00")
        narrative, _ = _narrative(project)
        self.assertIn("single version", narrative)
        self.assertIn("no change history to describe", narrative)

    def test_empty_project_is_described_honestly(self):
        project = Project("proj-empty", "Empty")
        actor = Actor.create("alice", "Alice")
        project.add_collaborator(actor)
        narrative, report = _narrative(project)
        self.assertIn("has no versions yet", narrative)
        self.assertIn("The record checks out", narrative)
        self.assertEqual(report.verdict, "clean")

    def test_dispute_case_narrative_matches(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        _upload(project, actors, "bob", "One. Two. Three.", "v2",
                "2026-11-02T00:00:00+00:00")
        narrative, report = _narrative(project, kind="build_dispute_case")
        self.assertIn("Alice", narrative)
        self.assertIn("Bob", narrative)
        self.assertIn("2 version(s)", narrative)
        self.assertEqual(report.verdict, "clean")


class TestScribeProblems(unittest.TestCase):
    def test_narrative_names_verification_problems(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        version = project.versions[0]
        project._blobs[version.content_id] = b"forged bytes"
        narrative, report = _narrative(project)
        self.assertIn("The record has problems", narrative)
        self.assertIn("does not match its hash", narrative)
        self.assertEqual(report.verdict, "issues_found")

    def test_narrative_names_a_rewrite(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two. Three. Four.", "v1",
                "2026-11-01T00:00:00+00:00")
        _upload(project, actors, "alice", "Five. Six. Seven. Eight.", "v2",
                "2026-11-02T00:00:00+00:00")
        narrative, _ = _narrative(project)
        self.assertIn("rewrote most of the document", narrative)
        self.assertIn("Things that stood out", narrative)


if __name__ == "__main__":
    unittest.main()
