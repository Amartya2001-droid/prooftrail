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

    def test_bundle_carries_declarations_coverage_keys_and_timestamp(self):
        designer, project, texts = make_project()
        project.declare(designer, project.versions[2], "ChatGPT",
                        "Rewrite tagline", [], "2026-10-24T15:00:00Z")
        bundle = build_evidence_bundle(
            project, texts, designer.secret_key, designer.public_key,
            contribution_coverage={"ai-assisted": 25.0},
            exported_at="2026-10-28T12:00:00Z")
        self.assertEqual(bundle["exported_at"], "2026-10-28T12:00:00Z")
        self.assertEqual(bundle["contribution_coverage_pct"],
                         {"ai-assisted": 25.0})
        self.assertEqual(len(bundle["declarations"]), 1)
        self.assertEqual(bundle["declarations"][0]["tool"], "ChatGPT")
        self.assertIn("designer", bundle["actor_public_keys"])
        self.assertIn("client", bundle["actor_public_keys"])
        self.assertEqual(bundle["self_approvals"], [])
        self.assertEqual(verify_evidence_bundle(bundle), [])

    def test_forged_ledger_events_fail_even_when_resigned(self):
        # A malicious exporter re-signing a bundle with forged events
        # must still fail: the owner signature proves who exported
        # it, not that the embedded history is genuine.
        import json

        from prooftrail.crypto import sign

        designer, project, texts = make_project()
        bundle = build_evidence_bundle(project, texts, designer.secret_key,
                                       designer.public_key)
        bundle["ledger_events"][0]["payload"] = {"label": "forged"}
        unsigned = {k: v for k, v in bundle.items()
                    if k not in ("owner_signature", "owner_public_key")}
        payload = json.dumps(unsigned, sort_keys=True,
                             separators=(",", ":")).encode()
        bundle["owner_signature"] = sign(
            designer.secret_key, designer.public_key, payload).hex()
        problems = verify_evidence_bundle(bundle)
        self.assertTrue(any("ledger:" in p and "signature invalid" in p
                            for p in problems))

    def test_bundle_without_actor_keys_cannot_verify_chain(self):
        import json

        from prooftrail.crypto import sign

        designer, project, texts = make_project()
        bundle = build_evidence_bundle(project, texts, designer.secret_key,
                                       designer.public_key)
        del bundle["actor_public_keys"]
        # Re-sign so the only failure is the missing keys, not the
        # signature over the changed payload.
        unsigned = {k: v for k, v in bundle.items()
                    if k not in ("owner_signature", "owner_public_key")}
        payload = json.dumps(unsigned, sort_keys=True,
                             separators=(",", ":")).encode()
        bundle["owner_signature"] = sign(
            designer.secret_key, designer.public_key, payload).hex()
        problems = verify_evidence_bundle(bundle)
        self.assertEqual(problems, [
            "bundle does not include actor public keys; "
            "ledger chain cannot be re-verified"])

    def test_contribution_map_feeds_page(self):
        _, project, texts = make_project()
        decl = Declaration("v3", "designer", "ChatGPT",
                           "Rewrite tagline, add pricing section")
        cmap = build_map([("v1", texts[0]), ("v2", texts[1]), ("v3", texts[2])],
                         [decl])
        page = verification_page(project, texts, cmap.coverage())
        self.assertGreater(page["contribution_coverage_pct"]["ai-assisted"], 0)

    def test_self_approval_is_flagged_not_hidden(self):
        designer, project, texts = make_project()
        # The fixture already has a client approval of v2; add a
        # designer self-approval of v3.
        project.approve(designer, project.versions[2], "2026-10-24T14:00:00Z")
        page = verification_page(project, texts)
        self.assertEqual(page["self_approvals"], [{
            "label": "v3",
            "content_id": project.versions[2].content_id,
            "actor": "designer",
        }])

    def test_independent_approval_is_not_flagged(self):
        _, project, texts = make_project()
        page = verification_page(project, texts)
        self.assertEqual(page["self_approvals"], [])

    def test_swapped_blob_content_is_caught(self):
        designer, project, texts = make_project()
        self.assertEqual(project.verify(), [])
        # Swap v1's bytes for different bytes under the same id: the
        # chain still vouches for the id, so only a content-hash check
        # catches that the stored bytes are no longer the version.
        project._blobs[project.versions[0].content_id] = b"forged bytes"
        problems = project.verify()
        self.assertTrue(any("does not match its hash" in p
                            for p in problems))


if __name__ == "__main__":
    unittest.main()
