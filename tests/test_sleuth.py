"""Sleuth (detective): real anomaly detection.

Sudden rewrites and authorship flips from sentence diffs between
consecutive versions; undeclared AI use checked against the
declarations on record (absence of a declaration is reported as
such, never as proof of AI use); timeline gaps from version
timestamps. A restore is named as a restore, not mistaken for a
rewrite."""

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


def _detective_findings(project):
    report = Orchestrator(project).run({"kind": "verify_project"})
    findings = [f for f in report.findings if f.agent_id == "detective"]
    return findings, report


class TestSleuthClean(unittest.TestCase):
    def test_no_anomalies_on_quiet_project(self):
        project, actors = _project()
        _upload(project, actors, "alice", "First draft. Second sentence.",
                "v1", "2026-11-01T00:00:00+00:00")
        findings, report = _detective_findings(project)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")
        self.assertIn("No anomalies found", findings[0].message)
        self.assertIn("No anomalies found",
                      report.summaries["detective"])

    def test_small_authorship_change_is_not_a_flip(self):
        project, actors = _project()
        text = " ".join(f"Sentence {n}." for n in range(1, 11))
        _upload(project, actors, "alice", text, "v1",
                "2026-11-01T00:00:00+00:00")
        changed = " ".join(
            [f"Sentence {n}." for n in range(1, 10)]
            + ["A different last sentence."])
        _upload(project, actors, "bob", changed, "v2",
                "2026-11-02T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        self.assertFalse(any("Authorship changed" in f.message
                             for f in findings))
        self.assertTrue(any("No anomalies found" in f.message
                            for f in findings))


class TestSleuthRewritesAndFlips(unittest.TestCase):
    def test_sudden_rewrite_is_flagged(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two. Three. Four.", "v1",
                "2026-11-01T00:00:00+00:00")
        _upload(project, actors, "alice", "Five. Six. Seven. Eight.", "v2",
                "2026-11-02T00:00:00+00:00")
        findings, report = _detective_findings(project)
        bad = [f for f in findings if f.severity == "medium"]
        self.assertEqual(len(bad), 1)
        self.assertIn("'v2'", bad[0].message)
        self.assertIn("rewrote most of the document", bad[0].message)
        self.assertIn("100% new", bad[0].message)
        self.assertIn("100% removed", bad[0].message)
        # 2 anomalies: the rewrite itself plus the 4 added sentences
        # with no declaration on record.
        self.assertIn("2 anomaly", report.summaries["detective"])
        # Medium findings do not escalate the verdict past clean.
        self.assertEqual(report.verdict, "clean")

    def test_authorship_flip_is_flagged(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two. Three.", "v1",
                "2026-11-01T00:00:00+00:00")
        _upload(project, actors, "bob", "One. Two. Three. Four.", "v2",
                "2026-11-02T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        flips = [f for f in findings if "Authorship changed" in f.message]
        self.assertEqual(len(flips), 1)
        self.assertIn("alice to bob", flips[0].message)
        self.assertIn("'v2'", flips[0].message)
        self.assertEqual(flips[0].severity, "medium")

    def test_restore_is_named_not_flagged_as_rewrite(self):
        project, actors = _project()
        first = _upload(project, actors, "alice",
                        "One. Two. Three. Four.", "v1",
                        "2026-11-01T00:00:00+00:00")
        _upload(project, actors, "alice", "Five. Six. Seven. Eight.", "v2",
                "2026-11-02T00:00:00+00:00")
        project.restore(actors["alice"], first, "2026-11-03T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        # v2 is a genuine rewrite; the restore of v1 is not.
        rewrites = [f for f in findings if "rewrote" in f.message]
        self.assertEqual(len(rewrites), 1)
        self.assertIn("'v2'", rewrites[0].message)
        restored = [f for f in findings if "restored" in f.message]
        self.assertEqual(len(restored), 1)
        self.assertIn("rollback", restored[0].message)


class TestSleuthDeclarations(unittest.TestCase):
    def test_undeclared_additions_are_flagged_honestly(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        _upload(project, actors, "alice",
                "One. Two. Three. Four. Five. Six.", "v2",
                "2026-11-02T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        flagged = [f for f in findings
                   if "no AI-use declaration" in f.message]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "low")
        self.assertIn("added 4 sentences", flagged[0].message)
        self.assertIn("not proof of authorship", flagged[0].message)

    def test_partial_declaration_coverage_is_flagged(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        v2 = _upload(project, actors, "alice",
                     "One. Two. Three. Four. Five. Six. Seven. Eight.",
                     "v2", "2026-11-02T00:00:00+00:00")
        project.declare(actors["alice"], v2, "ChatGPT",
                        sentence_indices=[2, 3],
                        timestamp="2026-11-02T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        flagged = [f for f in findings if "covers 2 of 6" in f.message]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "low")
        self.assertIn("ChatGPT", flagged[0].message)

    def test_full_declaration_clears_the_version(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        v2 = _upload(project, actors, "alice",
                     "One. Two. Three. Four. Five. Six.", "v2",
                     "2026-11-02T00:00:00+00:00")
        project.declare(actors["alice"], v2, "ChatGPT",
                        timestamp="2026-11-02T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        self.assertFalse(any("no AI-use declaration" in f.message
                             for f in findings))
        self.assertFalse(any("covers" in f.message and "added sentences"
                             in f.message for f in findings))

    def test_declaration_covering_nothing_is_flagged(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-01T00:00:00+00:00")
        v2 = _upload(project, actors, "alice", "One. Two.", "v2",
                     "2026-11-02T00:00:00+00:00")
        project.declare(actors["alice"], v2, "ChatGPT",
                        timestamp="2026-11-02T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        flagged = [f for f in findings if "covers nothing" in f.message]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "low")


class TestSleuthTimeline(unittest.TestCase):
    def test_long_gap_is_flagged(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-01-01T00:00:00+00:00")
        _upload(project, actors, "alice", "One. Two. Three.", "v2",
                "2026-02-15T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        gaps = [f for f in findings if "days passed" in f.message]
        self.assertEqual(len(gaps), 1)
        self.assertIn("45 days", gaps[0].message)
        self.assertEqual(gaps[0].severity, "info")

    def test_out_of_order_timestamps_are_flagged(self):
        project, actors = _project()
        _upload(project, actors, "alice", "One. Two.", "v1",
                "2026-11-02T00:00:00+00:00")
        _upload(project, actors, "alice", "One. Two. Three.", "v2",
                "2026-11-01T00:00:00+00:00")
        findings, _ = _detective_findings(project)
        flagged = [f for f in findings
                   if "before its parent" in f.message]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "medium")


if __name__ == "__main__":
    unittest.main()
