import unittest

from prooftrail.diffing import diff_texts


class TestDiffing(unittest.TestCase):
    def test_rewrite_detected(self):
        old = "We sell shoes. Our store is in Halifax. Prices are low."
        new = ("Step into a world of effortless style and comfort. "
               "Every pair is crafted for people on the move. "
               "Discover the collection today.")
        result = diff_texts(old, new)
        self.assertEqual(result.intent, "rewrite")
        self.assertAlmostEqual(result.new_sentence_pct, 100.0)

    def test_expansion_detected(self):
        old = "We sell shoes. Our store is in Halifax."
        new = ("We sell shoes. Our store is in Halifax. "
               "We also stock boots and sandals. Delivery is free over fifty dollars.")
        result = diff_texts(old, new)
        self.assertEqual(result.intent, "expansion")
        self.assertEqual(len(result.added), 2)
        self.assertEqual(len(result.removed), 0)

    def test_touch_up_detected(self):
        old = " ".join(f"Sentence number {i}." for i in range(10))
        new = old.replace("Sentence number 3.", "Sentence number three.")
        result = diff_texts(old, new)
        self.assertEqual(result.intent, "touch-up")

    def test_summary_mentions_counts(self):
        result = diff_texts("Alpha one. Alpha two.", "Alpha one. Beta three.")
        self.assertIn("1 sentence(s) added", result.summary())
        self.assertIn("1 removed", result.summary())


if __name__ == "__main__":
    unittest.main()
