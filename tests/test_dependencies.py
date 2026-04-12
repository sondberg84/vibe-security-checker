"""
Tests for OSV-backed dependency checker.
Includes unit tests (mocked network) and one live smoke test.
"""
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from check_dependencies import (
    DependencyChecker,
    query_osv_batch,
    _osv_severity,
    _cvss_severity,
    ECOSYSTEM_PYPI,
    ECOSYSTEM_NPM,
)


def make_project(files: dict) -> str:
    """Write files to a temp dir and return its path."""
    tmpdir = tempfile.mkdtemp()
    for name, content in files.items():
        p = Path(tmpdir) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmpdir


FAKE_VULN = {
    "id": "GHSA-test-1234-5678",
    "aliases": ["CVE-2023-99999"],
    "summary": "Remote code execution in testpkg",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [],
}


class TestCvssMapping(unittest.TestCase):

    def test_critical_threshold(self):
        self.assertEqual(_cvss_severity(9.5), "CRITICAL")

    def test_high_threshold(self):
        self.assertEqual(_cvss_severity(7.0), "HIGH")
        self.assertEqual(_cvss_severity(8.9), "HIGH")

    def test_medium_threshold(self):
        self.assertEqual(_cvss_severity(5.0), "MEDIUM")

    def test_low_threshold(self):
        self.assertEqual(_cvss_severity(2.0), "LOW")


class TestOsvSeverityParsing(unittest.TestCase):

    def test_database_specific_severity(self):
        vuln = {"database_specific": {"severity": "HIGH"}, "affected": []}
        label, _ = _osv_severity(vuln)
        self.assertEqual(label, "HIGH")

    def test_moderate_mapped_to_medium(self):
        vuln = {"database_specific": {"severity": "MODERATE"}, "affected": []}
        label, _ = _osv_severity(vuln)
        self.assertEqual(label, "MEDIUM")

    def test_npm_ecosystem_specific(self):
        vuln = {
            "database_specific": {},
            "affected": [{"ecosystem_specific": {"severity": "high"}}],
        }
        label, _ = _osv_severity(vuln)
        self.assertEqual(label, "HIGH")

    def test_unknown_defaults_to_high(self):
        vuln = {"database_specific": {}, "affected": []}
        label, _ = _osv_severity(vuln)
        self.assertEqual(label, "HIGH")


class TestHallucinatedPackages(unittest.TestCase):

    def test_python_hallucinated_package_flagged(self):
        tmpdir = make_project({"requirements.txt": "flask-security-utils==1.0.0\n"})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[]]):
            findings = checker.check()
        hallucinated = [f for f in findings if f.issue_type == "hallucinated"]
        self.assertEqual(len(hallucinated), 1)
        self.assertEqual(hallucinated[0].severity, "CRITICAL")

    def test_npm_hallucinated_package_flagged(self):
        pkg_json = json.dumps({"dependencies": {"react-utils": "^1.0.0"}})
        tmpdir = make_project({"package.json": pkg_json})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[]]):
            findings = checker.check()
        hallucinated = [f for f in findings if f.issue_type == "hallucinated"]
        self.assertEqual(len(hallucinated), 1)

    def test_real_package_not_flagged_as_hallucinated(self):
        tmpdir = make_project({"requirements.txt": "requests==2.31.0\n"})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[]]):
            findings = checker.check()
        hallucinated = [f for f in findings if f.issue_type == "hallucinated"]
        self.assertEqual(len(hallucinated), 0)


class TestOsvVulnerabilityDetection(unittest.TestCase):

    def test_vulnerable_package_creates_finding(self):
        tmpdir = make_project({"requirements.txt": "requests==2.27.0\n"})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[FAKE_VULN]]):
            findings = checker.check()
        vulns = [f for f in findings if f.issue_type == "vulnerable"]
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].cve_id, "CVE-2023-99999")
        self.assertEqual(vulns[0].severity, "CRITICAL")
        self.assertIn("Remote code execution", vulns[0].description)

    def test_clean_package_no_finding(self):
        tmpdir = make_project({"requirements.txt": "requests==2.31.0\n"})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[]]):
            findings = checker.check()
        vulns = [f for f in findings if f.issue_type == "vulnerable"]
        self.assertEqual(len(vulns), 0)

    def test_multiple_vulns_per_package(self):
        vuln2 = {**FAKE_VULN, "id": "GHSA-test-9999-0000", "aliases": ["CVE-2023-88888"]}
        tmpdir = make_project({"requirements.txt": "requests==2.27.0\n"})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[FAKE_VULN, vuln2]]):
            findings = checker.check()
        vulns = [f for f in findings if f.issue_type == "vulnerable"]
        self.assertEqual(len(vulns), 2)

    def test_osv_offline_does_not_crash(self):
        """If OSV is unreachable, checker should degrade gracefully."""
        tmpdir = make_project({"requirements.txt": "requests==2.27.0\n"})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", side_effect=Exception("network error")):
            findings = checker.check()
        # Should not raise; OSV findings just won't appear
        vulns = [f for f in findings if f.issue_type == "vulnerable"]
        self.assertEqual(len(vulns), 0)

    def test_npm_vulnerable_package(self):
        pkg_json = json.dumps({"dependencies": {"lodash": "4.17.20"}})
        tmpdir = make_project({"package.json": pkg_json})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[FAKE_VULN]]):
            findings = checker.check()
        vulns = [f for f in findings if f.issue_type == "vulnerable"]
        self.assertEqual(len(vulns), 1)


class TestUnpinnedVersions(unittest.TestCase):

    def test_wildcard_version_flagged(self):
        pkg_json = json.dumps({"dependencies": {"express": "*"}})
        tmpdir = make_project({"package.json": pkg_json})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[]]):
            findings = checker.check()
        suspicious = [f for f in findings if f.issue_type == "suspicious"]
        self.assertEqual(len(suspicious), 1)

    def test_latest_version_flagged(self):
        pkg_json = json.dumps({"dependencies": {"react": "latest"}})
        tmpdir = make_project({"package.json": pkg_json})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[]]):
            findings = checker.check()
        suspicious = [f for f in findings if f.issue_type == "suspicious"]
        self.assertEqual(len(suspicious), 1)

    def test_pinned_version_not_flagged(self):
        pkg_json = json.dumps({"dependencies": {"react": "18.2.0"}})
        tmpdir = make_project({"package.json": pkg_json})
        checker = DependencyChecker(tmpdir)
        with patch("check_dependencies.query_osv_batch", return_value=[[]]):
            findings = checker.check()
        suspicious = [f for f in findings if f.issue_type == "suspicious"]
        self.assertEqual(len(suspicious), 0)


class TestOsvLive(unittest.TestCase):
    """Smoke test against real OSV API — skipped if network unavailable."""

    def test_known_vulnerable_requests_version(self):
        """requests 2.27.0 has known CVEs — OSV should return results."""
        try:
            results = query_osv_batch([
                {"name": "requests", "ecosystem": ECOSYSTEM_PYPI, "version": "2.27.0"}
            ])
        except Exception:
            self.skipTest("OSV API not reachable")
        self.assertGreater(len(results[0]), 0, "Expected CVEs for requests 2.27.0")

    def test_unknown_package_returns_empty(self):
        """A package with no known vulnerabilities should return empty."""
        try:
            results = query_osv_batch([
                {"name": "colorama", "ecosystem": ECOSYSTEM_PYPI, "version": "0.4.6"}
            ])
        except Exception:
            self.skipTest("OSV API not reachable")
        self.assertEqual(results[0], [], "Expected no CVEs for colorama 0.4.6")


if __name__ == "__main__":
    unittest.main()
