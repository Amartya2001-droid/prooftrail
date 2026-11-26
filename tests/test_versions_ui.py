"""Deterministic client history races, ordered with promises rather than sleeps."""
import shutil
import subprocess
import unittest
from pathlib import Path


class TestVersionsRequests(unittest.TestCase):
    def check_scenario(self, scenario):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node not installed")
        result = subprocess.run([node, "tests/js/versions_requests.cjs", scenario],
                                cwd=Path(__file__).resolve().parent.parent,
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: " + scenario, result.stdout)

    def test_newer_reset_wins_out_of_order(self):
        self.check_scenario("newer_reset_wins")

    def test_superseded_reset_waits_for_current_response(self):
        self.check_scenario("older_reset_waits")

    def test_project_switch_discards_old_data_and_errors(self):
        self.check_scenario("project_switch")

    def test_account_switch_discards_old_data(self):
        self.check_scenario("account_switch")

    def test_duplicate_next_page_issues_one_request(self):
        self.check_scenario("duplicate_page")

    def test_reset_invalidates_in_flight_page(self):
        self.check_scenario("reset_during_page")

    def test_page_failure_releases_lock_and_preserves_offset(self):
        self.check_scenario("page_failure_retry")

    def test_missing_selection_or_session_clears_rows(self):
        self.check_scenario("missing_selection")
