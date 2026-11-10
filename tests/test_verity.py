"""Verity (verifier): deep per-version verification.

Verity reports one finding per version — content hash, parent link,
timestamp — plus one finding for the ledger chain itself (hashes,
signatures, event order), so a failure names exactly where it is
instead of a single pass/fail for the whole project."""

import unittest

from prooftrail.agents import Orchestrator
from prooftrail.store import Actor, Project


def _project_with_versions(texts, timestamps=None, actor_id="alice"):
    project = Project("proj-1", "Brand deck")
    actor = Actor.create(actor_id, "Alice")
    project.add_collaborator(actor)
    stamps = timestamps or [
        f"2026-11-0{i + 1}T00:00:00+00:00" for i in range(len(texts))]
    for i, text in enumerate(texts):
        project.upload(actor, text.encode(), stamps[i], label=f"v{i + 1}")
    return project


def _verity_findings(project):
    report = Orchestrator(project).run({"kind": "verify_project"})
    return [f for f in report.findings if f.agent_id == "verifier"], report


class TestVerityClean(unittest.TestCase):
    def test_chain_and_version_findings_on_clean_project(self):
        project = _project_with_versions(["First draft. Second sentence."])
        findings, report = _verity_findings(project)
        self.assertEqual(len(findings), 2)
        chain, version = findings
        self.assertEqual(chain.severity, "info")
        # 2 events: the upload plus the agent_run_started event the
        # orchestrator appends before dispatching Verity.
        self.assertIn("Ledger chain verified: 2 events", chain.message)
        self.assertEqual(version.severity, "info")
        self.assertIn("'v1'", version.message)
        self.assertIn("content hash matches", version.message)
        self.assertIn("Verified ledger: 2 events, 1 version(s), no problems.",
                      report.summaries["verifier"])

    def test_one_finding_per_version(self):
        project = _project_with_versions([
            "First draft. Second sentence.",
            "First draft. Second sentence. Third sentence added.",
            "First draft. Third sentence added. Fourth sentence.",
        ])
        findings, _ = _verity_findings(project)
        self.assertEqual(len(findings), 4)  # chain + 3 versions
        labels = [f.message for f in findings[1:]]
        self.assertIn("'v1'", labels[0])
        self.assertIn("'v2'", labels[1])
        self.assertIn("'v3'", labels[2])
        self.assertTrue(all(f.severity == "info" for f in findings))

    def test_empty_project_reports_chain_only(self):
        project = Project("proj-empty", "Empty")
        actor = Actor.create("alice", "Alice")
        project.add_collaborator(actor)
        findings, report = _verity_findings(project)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")
        # 1 event: the agent_run_started event the orchestrator
        # appends before dispatching Verity.
        self.assertIn("1 events", findings[0].message)
        self.assertIn("0 version(s)", report.summaries["verifier"])


class TestVerityFailures(unittest.TestCase):
    def test_tampered_blob_blames_that_version(self):
        project = _project_with_versions(["First draft. Second sentence."])
        version = project.versions[0]
        project._blobs[version.content_id] = b"forged bytes"
        findings, report = _verity_findings(project)
        bad = [f for f in findings if f.severity == "high"]
        self.assertEqual(len(bad), 1)
        self.assertIn("'v1'", bad[0].message)
        self.assertIn("does not match its hash",
                      " ".join(bad[0].evidence))
        self.assertEqual(report.verdict, "issues_found")

    def test_broken_parent_link_blames_that_version(self):
        project = _project_with_versions([
            "First draft. Second sentence.",
            "First draft. Second sentence. Third sentence added.",
        ])
        project.versions[1].parent_content_id = "0" * 64
        findings, _ = _verity_findings(project)
        bad = [f for f in findings if f.severity == "high"]
        self.assertEqual(len(bad), 1)
        self.assertIn("'v2'", bad[0].message)
        self.assertIn("parent linkage broken",
                      " ".join(bad[0].evidence))
        # The clean version and the chain still pass.
        self.assertEqual(
            [f for f in findings if f.severity == "info"][0].message[:13],
            "Ledger chain ")

    def test_tampered_event_blames_the_chain(self):
        project = _project_with_versions(["First draft. Second sentence."])
        project.ledger.events[0]["payload"]["label"] = "forged"
        findings, _ = _verity_findings(project)
        bad = [f for f in findings if f.severity == "high"]
        self.assertTrue(bad)
        self.assertIn("Ledger chain has", bad[0].message)
        self.assertIn("hash mismatch", " ".join(bad[0].evidence))
        # The version itself is untouched, so it still passes.
        self.assertTrue(any("'v1'" in f.message and f.severity == "info"
                            for f in findings))

    def test_version_before_its_parent_is_flagged(self):
        project = _project_with_versions(
            ["First draft. Second sentence.",
             "First draft. Second sentence. Third sentence added."],
            timestamps=["2026-11-02T00:00:00+00:00",
                        "2026-11-01T00:00:00+00:00"])
        findings, _ = _verity_findings(project)
        bad = [f for f in findings if f.severity == "high"]
        # Both: the version finding (its timestamp precedes v1) and
        # the chain finding (the v2 upload event carries the same
        # timestamp, so it also runs backwards along the chain).
        self.assertEqual(len(bad), 2)
        version_bad = next(f for f in bad if "'v2'" in f.message)
        self.assertIn("earlier than the previous version",
                      " ".join(version_bad.evidence))
        chain_bad = next(f for f in bad
                         if f.message.startswith("Ledger chain"))
        self.assertIn("earlier than the previous event",
                      " ".join(chain_bad.evidence))

    def test_unparseable_version_timestamp_is_flagged(self):
        project = _project_with_versions(["First draft. Second sentence."],
                                         timestamps=["not-a-timestamp"])
        findings, _ = _verity_findings(project)
        bad = [f for f in findings if f.severity == "high"]
        # Both: the version finding and the chain finding, because
        # the upload event carries the same unparseable timestamp.
        self.assertEqual(len(bad), 2)
        version_bad = next(f for f in bad if "'v1'" in f.message)
        self.assertIn("not a valid ISO timestamp",
                      " ".join(version_bad.evidence))
        chain_bad = next(f for f in bad
                         if f.message.startswith("Ledger chain"))
        self.assertIn("not a valid ISO timestamp",
                      " ".join(chain_bad.evidence))


if __name__ == "__main__":
    unittest.main()
