import unittest

from prooftrail.contributions import Declaration, build_map


class TestContributionMap(unittest.TestCase):
    def test_declared_ai_version_marks_added_sentences(self):
        versions = [
            ("v1", "We sell shoes. Our store is in Halifax."),
            ("v2", "We sell shoes. Our store is in Halifax. "
                   "Step into effortless style and comfort."),
        ]
        decl = Declaration("v2", "designer", "ChatGPT",
                           "Rewrite the tagline to be more persuasive")
        cmap = build_map(versions, [decl])
        sources = [s.source for s in cmap.segments]
        # v1 sentences (human) + v2 carried over (human) + v2 added (ai-assisted)
        self.assertEqual(sources[-1], "ai-assisted")
        self.assertEqual(sources.count("human"), 4)

    def test_undeclared_additions_stay_human_with_caveat(self):
        versions = [("v1", "Alpha one."), ("v2", "Alpha one. Beta two.")]
        cmap = build_map(versions)
        self.assertEqual(cmap.segments[-1].source, "human")
        self.assertIn("not proof of authorship", cmap.caveat)

    def test_override_tags_imported_passage(self):
        versions = [("v1", "Our story begins here. Licensed photo caption.")]
        cmap = build_map(versions, overrides={("v1", 1): "imported"})
        self.assertEqual(cmap.segments[1].source, "imported")
        self.assertGreater(cmap.coverage()["imported"], 0)


if __name__ == "__main__":
    unittest.main()
