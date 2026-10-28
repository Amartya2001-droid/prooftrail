import unittest

from prooftrail.store import Actor, Project


class TestDeclarations(unittest.TestCase):
    def setUp(self):
        self.designer = Actor.create("designer", "Freelance Designer")
        self.client = Actor.create("client", "Client")
        self.project = Project("brand-deck", "Brand Deck")
        self.project.add_collaborator(self.designer)
        self.project.add_collaborator(self.client)
        self.v1 = self.project.upload(
            self.designer, b"First sentence. Second sentence.",
            "2026-10-24T10:00:00Z", "v1")
        self.v2 = self.project.upload(
            self.designer, b"First sentence. Second sentence. Third, new one.",
            "2026-10-24T11:00:00Z", "v2")

    def test_declare_records_signed_ledger_event(self):
        event = self.project.declare(
            self.designer, self.v2, "ChatGPT", "drafted the closing line",
            sentence_indices=[2], timestamp="2026-10-24T11:30:00Z")
        self.assertEqual(event["type"], "declaration")
        self.assertEqual(event["actor"], "designer")
        self.assertEqual(self.project.verify(), [])
        decls = self.project.declarations()
        self.assertEqual(len(decls), 1)
        self.assertEqual(decls[0].version_label, "v2")
        self.assertEqual(decls[0].tool, "ChatGPT")
        self.assertEqual(decls[0].prompt_summary, "drafted the closing line")
        self.assertEqual(decls[0].sentence_indices, [2])

    def test_declare_without_indices_means_all_added(self):
        self.project.declare(self.designer, self.v2, "Claude")
        self.assertEqual(self.project.declarations()[0].sentence_indices, [])

    def test_tampered_declaration_breaks_chain(self):
        self.project.declare(self.designer, self.v2, "ChatGPT")
        self.project.ledger.events[-1]["payload"]["tool"] = "Someone else"
        self.assertNotEqual(self.project.verify(), [])

    def test_declare_rejects_non_collaborator(self):
        outsider = Actor.create("outsider", "Outsider")
        with self.assertRaises(ValueError):
            self.project.declare(outsider, self.v2, "ChatGPT")

    def test_declare_rejects_foreign_version(self):
        other = Project("other", "Other")
        other.add_collaborator(self.designer)
        foreign = other.upload(self.designer, b"Elsewhere.",
                               "2026-10-24T12:00:00Z", "x")
        with self.assertRaises(ValueError):
            self.project.declare(self.designer, foreign, "ChatGPT")

    def test_declare_rejects_bad_tool_and_prompt(self):
        with self.assertRaises(ValueError):
            self.project.declare(self.designer, self.v2, "   ")
        with self.assertRaises(ValueError):
            self.project.declare(self.designer, self.v2, "x" * 101)
        with self.assertRaises(ValueError):
            self.project.declare(self.designer, self.v2, "ChatGPT",
                                 prompt_summary="y" * 501)

    def test_declare_rejects_out_of_range_sentence(self):
        with self.assertRaises(ValueError):
            self.project.declare(self.designer, self.v2, "ChatGPT",
                                 sentence_indices=[3])
        with self.assertRaises(ValueError):
            self.project.declare(self.designer, self.v2, "ChatGPT",
                                 sentence_indices=[-1])

    def test_declare_rejects_exact_duplicate(self):
        self.project.declare(self.designer, self.v2, "ChatGPT",
                             sentence_indices=[2])
        with self.assertRaises(ValueError) as ctx:
            self.project.declare(self.designer, self.v2, "ChatGPT",
                                 "a different summary",
                                 sentence_indices=[2])
        self.assertIn("duplicate", str(ctx.exception))
        self.assertEqual(len(self.project.declarations()), 1)

    def test_declare_allows_different_tool_or_coverage(self):
        self.project.declare(self.designer, self.v2, "ChatGPT",
                             sentence_indices=[2])
        self.project.declare(self.designer, self.v2, "Claude",
                             sentence_indices=[2])
        self.project.declare(self.designer, self.v2, "ChatGPT",
                             sentence_indices=[1])
        self.assertEqual(len(self.project.declarations()), 3)


if __name__ == "__main__":
    unittest.main()
