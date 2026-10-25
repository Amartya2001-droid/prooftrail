import unittest

from prooftrail.contributions import Declaration, build_map
from prooftrail.store import Actor, Project
from prooftrail.verification import (
    build_evidence_bundle,
    verification_page,
    verify_evidence_bundle,
)


def make_project():
    designer = Actor.create("designer", "Freelance Designer")
    client = Actor.create("client", "Client")
    project = Project("brand-deck", "Brand Deck")
    project.add_collaborator(designer)
    project.add_collaborator(client)
    texts = [
        "We sell shoes. Our store is in Halifax.",
        "We sell shoes. Our store is in Halifax. Delivery is free over fifty dollars.",
        "We sell shoes. Our store is in Halifax. Delivery is free over fifty dollars. "
        "Step into effortless style and comfort. Pricing starts at ninety dollars.",
    ]
    for i, text in enumerate(texts):
        project.upload(designer, text.encode(), f"2026-10-24T1{i}:00:00Z", f"v{i+1}")
    project.approve(client, project.versions[1], "2026-10-24T13:00:00Z")
    return designer, project, texts


class TestVerification(unittest.TestCase):
    def test_page_has_hashes_not_content(self):
        _, project, texts = make_project()
        page = verification_page(project, texts)
        self.assertTrue(page["ledger_valid"])
        self.assertEqual(len(page["versions"]), 3)
        blob = str(page)
        self.assertNotIn("We sell shoes", blob)
        self.assertIn("sha256:", blob)

    def test_bundle_roundtrip_and_tamper(self):
        designer, project, texts = make_project()
        bundle = build_evidence_bundle(project, texts, designer.secret_key,
                                       designer.public_key,
                                       claim="Original authorship of brand deck")
        self.assertEqual(verify_evidence_bundle(bundle), [])
        bundle["versions"][0]["content"] = "We stole shoes."
        self.assertTrue(any("does not match its hash" in p
                            for p in verify_evidence_bundle(bundle)))

    def test_contribution_map_feeds_page(self):
        _, project, texts = make_project()
        decl = Declaration("v3", "designer", "ChatGPT",
                           "Rewrite tagline, add pricing section")
        cmap = build_map([("v1", texts[0]), ("v2", texts[1]), ("v3", texts[2])],
                         [decl])
        page = verification_page(project, texts, cmap.coverage())
        self.assertGreater(page["contribution_coverage_pct"]["ai-assisted"], 0)


if __name__ == "__main__":
    unittest.main()
