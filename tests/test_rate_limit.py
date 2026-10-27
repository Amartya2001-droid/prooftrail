import unittest

from prooftrail import server as server_module
from prooftrail.server import ApiError, ProofTrailApp


class TestRegistrationRateLimit(unittest.TestCase):
    def setUp(self):
        # Narrow the cap for the test; production default is 30/hour/IP.
        self._orig_max = server_module.REGISTER_MAX_PER_IP
        server_module.REGISTER_MAX_PER_IP = 3
        self.app = ProofTrailApp()

    def tearDown(self):
        server_module.REGISTER_MAX_PER_IP = self._orig_max

    def test_cap_per_address(self):
        for i in range(3):
            self.app.register(f"user{i}", "User", "password123",
                              remote_addr="203.0.113.7")
        with self.assertRaises(ApiError) as ctx:
            self.app.register("user3", "User", "password123",
                              remote_addr="203.0.113.7")
        self.assertEqual(ctx.exception.status, 429)

    def test_other_address_unaffected(self):
        for i in range(3):
            self.app.register(f"user{i}", "User", "password123",
                              remote_addr="203.0.113.7")
        # A different address still has its full allowance.
        self.app.register("elsewhere", "User", "password123",
                          remote_addr="198.51.100.9")

    def test_no_address_means_no_limit(self):
        # Direct app-level callers (tests, scripts) without an address
        # are not rate-limited.
        for i in range(5):
            self.app.register(f"local{i}", "User", "password123")


if __name__ == "__main__":
    unittest.main()
