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
            self.app.register(f"user{i}", "User", "sunset-river-42",
                              remote_addr="203.0.113.7")
        with self.assertRaises(ApiError) as ctx:
            self.app.register("user3", "User", "sunset-river-42",
                              remote_addr="203.0.113.7")
        self.assertEqual(ctx.exception.status, 429)

    def test_other_address_unaffected(self):
        for i in range(3):
            self.app.register(f"user{i}", "User", "sunset-river-42",
                              remote_addr="203.0.113.7")
        # A different address still has its full allowance.
        self.app.register("elsewhere", "User", "sunset-river-42",
                          remote_addr="198.51.100.9")

    def test_no_address_means_no_limit(self):
        # Direct app-level callers (tests, scripts) without an address
        # are not rate-limited.
        for i in range(5):
            self.app.register(f"local{i}", "User", "sunset-river-42")


class TestLoginIpRateLimit(unittest.TestCase):
    def setUp(self):
        # Narrow the cap for the test; production default is 20/10min/IP.
        self._orig_max = server_module.LOGIN_IP_MAX_FAILURES
        server_module.LOGIN_IP_MAX_FAILURES = 3
        self.app = ProofTrailApp()
        self.app.register("victim", "Victim", "sunset-river-42")

    def tearDown(self):
        server_module.LOGIN_IP_MAX_FAILURES = self._orig_max

    def test_spray_across_usernames_hits_ip_limit(self):
        # Distinct usernames, so the per-username lockout never fires;
        # the address limit is what stops the spray.
        for name in ("a", "b", "c"):
            with self.assertRaises(ApiError) as ctx:
                self.app.login(name, "wrong", remote_addr="203.0.113.7")
            self.assertEqual(ctx.exception.status, 401)
        # Even valid credentials from that address are now refused.
        with self.assertRaises(ApiError) as ctx:
            self.app.login("victim", "sunset-river-42",
                           remote_addr="203.0.113.7")
        self.assertEqual(ctx.exception.status, 429)

    def test_other_address_unaffected(self):
        for name in ("a", "b", "c"):
            with self.assertRaises(ApiError):
                self.app.login(name, "wrong", remote_addr="203.0.113.7")
        result = self.app.login("victim", "sunset-river-42",
                                remote_addr="198.51.100.9")
        self.assertEqual(result["actor_id"], "victim")

    def test_no_address_means_no_ip_limit(self):
        for name in ("a", "b", "c", "d", "e"):
            with self.assertRaises(ApiError) as ctx:
                self.app.login(name, "wrong")
            self.assertEqual(ctx.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
