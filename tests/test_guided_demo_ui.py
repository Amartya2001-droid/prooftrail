"""Exercise lost-response recovery and duplicate-click guards in the client."""
import shutil
import subprocess
import unittest
from pathlib import Path


class TestGuidedDemoUI(unittest.TestCase):
    def test_resume_and_double_click_behavior(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node not installed")
        result = subprocess.run([node, "tests/js/guided_demo.cjs"],
                                cwd=Path(__file__).resolve().parent.parent,
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS:", result.stdout)
