"""
Tests for baseline / diff mode.
"""
import sys
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from scan_security import (
    SecurityScanner, Finding, Severity,
    save_baseline, load_baseline, apply_baseline,
)


def _finding(rule_id="SEC-013", snippet="api_key = 'abc123def456ghi789'",
             file_path="config.py", line=1):
    return Finding(
        rule_id=rule_id, severity=Severity.CRITICAL,
        category="Secrets", description="test",
        file_path=file_path, line_number=line,
        code_snippet=snippet, remediation="fix it",
    )


def scan_str(code: str, filename="test.py"):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / filename).write_text(textwrap.dedent(code))
        scanner = SecurityScanner(d)
        return scanner.scan()


class TestFingerprint(unittest.TestCase):

    def test_same_finding_same_fingerprint(self):
        f1 = _finding()
        f2 = _finding()
        self.assertEqual(f1.fingerprint(), f2.fingerprint())

    def test_different_rule_different_fingerprint(self):
        f1 = _finding(rule_id="SEC-013")
        f2 = _finding(rule_id="INJ-002")
        self.assertNotEqual(f1.fingerprint(), f2.fingerprint())

    def test_different_snippet_different_fingerprint(self):
        f1 = _finding(snippet="api_key = 'abc123'")
        f2 = _finding(snippet="api_key = 'xyz789'")
        self.assertNotEqual(f1.fingerprint(), f2.fingerprint())

    def test_line_number_change_same_fingerprint(self):
        """Fingerprint must survive line number shifts (refactoring)."""
        f1 = _finding(line=10)
        f2 = _finding(line=99)
        self.assertEqual(f1.fingerprint(), f2.fingerprint())

    def test_fingerprint_length(self):
        self.assertEqual(len(_finding().fingerprint()), 16)


class TestSaveLoadBaseline(unittest.TestCase):

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "baseline.json")
            result = scan_str('api_key = "abcdef1234567890abcdef"')
            save_baseline(result, path)

            loaded = load_baseline(path)
            self.assertIsInstance(loaded, set)
            for f in result.findings:
                self.assertIn(f.fingerprint(), loaded)

    def test_missing_file_returns_empty_set(self):
        loaded = load_baseline("/nonexistent/path/baseline.json")
        self.assertEqual(loaded, set())

    def test_baseline_file_contains_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "baseline.json")
            result = scan_str('api_key = "abcdef1234567890abcdef"')
            save_baseline(result, path)

            data = json.loads(Path(path).read_text())
            self.assertIn("created", data)
            self.assertIn("version", data)
            self.assertIn("fingerprints", data)
            self.assertIn("findings", data)


class TestApplyBaseline(unittest.TestCase):

    def test_all_suppressed_when_same(self):
        result = scan_str('api_key = "abcdef1234567890abcdef"')
        known = {f.fingerprint() for f in result.findings}
        new_findings, suppressed = apply_baseline(result, known)
        self.assertEqual(new_findings, [])
        self.assertEqual(suppressed, len(result.findings))

    def test_nothing_suppressed_when_empty_baseline(self):
        result = scan_str('api_key = "abcdef1234567890abcdef"')
        new_findings, suppressed = apply_baseline(result, set())
        self.assertEqual(len(new_findings), len(result.findings))
        self.assertEqual(suppressed, 0)

    def test_only_new_findings_returned(self):
        """Baseline has one finding; a second new one should surface."""
        f_old = _finding(rule_id="SEC-013", snippet="old_key = 'aaaa1111bbbb2222cccc'")
        f_new = _finding(rule_id="INJ-002", snippet="cursor.execute(f'SELECT {x}')")

        from scan_security import ScanResult
        result = ScanResult()
        result.findings = [f_old, f_new]

        known = {f_old.fingerprint()}
        new_findings, suppressed = apply_baseline(result, known)

        self.assertEqual(len(new_findings), 1)
        self.assertEqual(new_findings[0].rule_id, "INJ-002")
        self.assertEqual(suppressed, 1)

    def test_line_shift_does_not_create_false_new_finding(self):
        """
        If code moves (line number changes) but the vulnerable snippet is
        unchanged, it must still be suppressed by the baseline.
        """
        f_baseline = _finding(line=5)
        f_shifted  = _finding(line=50)   # same snippet, different line

        from scan_security import ScanResult
        result = ScanResult()
        result.findings = [f_shifted]

        known = {f_baseline.fingerprint()}
        new_findings, suppressed = apply_baseline(result, known)

        self.assertEqual(new_findings, [], "Line shift should not create a false new finding")
        self.assertEqual(suppressed, 1)


class TestBaselineEndToEnd(unittest.TestCase):

    def test_save_then_new_code_surfaces_new_finding(self):
        """
        Save a baseline, then scan code that has an additional vulnerability.
        Only the new finding should be reported.
        """
        existing_vuln = 'api_key = "abcdef1234567890abcdef"\n'
        new_vuln = 'cursor.execute(f"SELECT * FROM t WHERE id={x}")\n'

        with tempfile.TemporaryDirectory() as d:
            baseline_path = str(Path(d) / "baseline.json")

            # Step 1: scan existing code, save baseline
            result_v1 = scan_str(existing_vuln)
            save_baseline(result_v1, baseline_path)

            # Step 2: scan code with the old vuln + a new one
            result_v2 = scan_str(existing_vuln + new_vuln)
            known = load_baseline(baseline_path)
            new_findings, suppressed = apply_baseline(result_v2, known)

            new_rule_ids = {f.rule_id for f in new_findings}
            self.assertIn("INJ-002", new_rule_ids, "New SQL injection should be reported")
            # The pre-existing secret finding should be suppressed
            self.assertGreater(suppressed, 0, "Pre-existing finding should be suppressed")


if __name__ == "__main__":
    unittest.main()
