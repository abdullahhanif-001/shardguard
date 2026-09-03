"""Unit tests for SCSP scanner and gates."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestScanner(unittest.TestCase):
    def test_m01_detects_cross_file(self):
        from scsp.cross_file_taint import scan_directory

        findings, _ = scan_directory(ROOT / "fixtures" / "MOCK_" / "M01_shard_three_modules")
        critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        self.assertTrue(critical, "M01 should have CRITICAL findings")
        self.assertTrue(any(f.cross_file for f in critical))

    def test_m04_clean(self):
        from scsp.cross_file_taint import scan_directory

        findings, _ = scan_directory(ROOT / "fixtures" / "MOCK_" / "M04_benign_crypto")
        critical = [f for f in findings if f.severity in ("CRITICAL", "HIGH") and f.status == "DETECT"]
        self.assertEqual(len(critical), 0)

    def test_verify_self_pin(self):
        from scsp.integrity import pin_engine, verify_self

        pin_engine()
        ok, msg = verify_self()
        self.assertTrue(ok, msg)


class TestGates(unittest.TestCase):
    def test_g0_passes(self):
        from scsp.gates import run_g0

        result = run_g0()
        self.assertEqual(result["status"], "PASS", result.get("failures"))


if __name__ == "__main__":
    unittest.main()
