import copy
import unittest

from prooftrail.crypto import generate_keypair
from prooftrail.ledger import Ledger


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.secret, self.public = generate_keypair()
        self.ledger = Ledger("proj-demo")
        self.ledger.register_actor("designer", self.public)

    def test_chain_verifies(self):
        self.ledger.append("upload", "designer", self.secret,
                          content_id="sha256:aaa", timestamp="2026-10-24T10:00:00Z")
        self.ledger.append("edit", "designer", self.secret,
                          content_id="sha256:bbb", parent_content_id="sha256:aaa",
                          timestamp="2026-10-24T11:00:00Z")
        self.assertEqual(self.ledger.verify(), [])

    def test_tamper_detected(self):
        self.ledger.append("upload", "designer", self.secret,
                          content_id="sha256:aaa", timestamp="2026-10-24T10:00:00Z")
        self.ledger.append("edit", "designer", self.secret,
                          content_id="sha256:bbb", timestamp="2026-10-24T11:00:00Z")
        tampered = copy.deepcopy(self.ledger.events)
        tampered[0]["content_id"] = "sha256:evil"
        ledger2 = Ledger("proj-demo")
        ledger2.register_actor("designer", self.public)
        ledger2.events = tampered
        problems = ledger2.verify()
        self.assertTrue(any("hash mismatch" in p or "signature invalid" in p
                            for p in problems))

    def test_dropped_middle_event_detected(self):
        for cid in ("sha256:a", "sha256:b", "sha256:c"):
            self.ledger.append("upload", "designer", self.secret, content_id=cid)
        ledger2 = Ledger("proj-demo")
        ledger2.register_actor("designer", self.public)
        ledger2.events = [self.ledger.events[0], self.ledger.events[2]]
        self.assertTrue(any("prev_hash" in p or "index" in p
                            for p in ledger2.verify()))

    def test_unknown_actor_rejected(self):
        with self.assertRaises(ValueError):
            self.ledger.append("upload", "stranger", self.secret)


if __name__ == "__main__":
    unittest.main()
