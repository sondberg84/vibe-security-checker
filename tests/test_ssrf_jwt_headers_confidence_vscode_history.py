"""
Tests for:
  - SSRF detection (SSRF-001..005)
  - JWT misconfiguration (JWT-001..005)
  - Security header patterns (HDR-001..006)
  - Confidence scores on findings
  - VS Code output format (--vscode)
  - VS Code installer (install_vscode.py)
  - HTML report generation
  - Git history scanner (GitHistoryScanner — unit tests with mocked git)
"""
import sys
import io
import json
import tempfile
import textwrap
import unittest
import contextlib
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from scan_security import (
    SecurityScanner, ScanConfig, ScanResult, Finding, Severity,
    CONFIDENCE_MAP, print_results,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def scan(code: str, filename: str = "app.py", config: ScanConfig = None) -> ScanResult:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / filename).write_text(textwrap.dedent(code))
        return SecurityScanner(d, config=config).scan()


def rule_ids(result: ScanResult):
    return {f.rule_id for f in result.findings}


def scan_json(code: str, filename: str = "app.py") -> dict:
    result = scan(code, filename)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_results(result, json_output=True)
    return json.loads(buf.getvalue())


def scan_vscode(code: str, filename: str = "app.py") -> str:
    result = scan(code, filename)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_results(result, vscode_output=True)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# SSRF detection
# ─────────────────────────────────────────────────────────────────────────────

class TestSSRF(unittest.TestCase):

    def test_requests_with_user_input_detected(self):
        code = 'resp = requests.get(request.args.get("url"))\n'
        result = scan(code)
        self.assertIn("SSRF-001", rule_ids(result))

    def test_requests_hardcoded_url_not_flagged(self):
        code = 'resp = requests.get("https://api.example.com/data")\n'
        result = scan(code)
        self.assertNotIn("SSRF-001", rule_ids(result))

    def test_urllib_with_user_input_detected(self):
        code = 'urllib.request.urlopen(request.args["url"])\n'
        result = scan(code)
        self.assertIn("SSRF-002", rule_ids(result))

    def test_fetch_with_user_input_detected(self):
        code = 'const res = await fetch(req.query.url);\n'
        result = scan(code, filename="app.js")
        self.assertIn("SSRF-003", rule_ids(result))

    def test_fetch_hardcoded_url_not_flagged(self):
        code = 'const res = await fetch("https://api.example.com");\n'
        result = scan(code, filename="app.js")
        self.assertNotIn("SSRF-003", rule_ids(result))

    def test_axios_with_user_input_detected(self):
        code = 'const data = await axios.get(req.body.url);\n'
        result = scan(code, filename="app.js")
        self.assertIn("SSRF-004", rule_ids(result))

    def test_ssrf_python_rules_not_on_js(self):
        """SSRF-001 (requests) should not fire on .js files."""
        code = 'const r = requests.get(request.args.url);\n'
        result = scan(code, filename="app.js")
        self.assertNotIn("SSRF-001", rule_ids(result))

    def test_ssrf_js_rules_not_on_python(self):
        """SSRF-003 (fetch) should not fire on .py files."""
        code = 'fetch(req.query.url)\n'
        result = scan(code, filename="app.py")
        self.assertNotIn("SSRF-003", rule_ids(result))


# ─────────────────────────────────────────────────────────────────────────────
# JWT misconfiguration
# ─────────────────────────────────────────────────────────────────────────────

class TestJWT(unittest.TestCase):

    def test_algorithm_none_detected(self):
        code = 'token = jwt.decode(t, key, algorithms="none")\n'
        result = scan(code)
        self.assertIn("JWT-001", rule_ids(result))

    def test_verify_false_detected(self):
        code = 'payload = jwt.decode(token, options={"verify": False})\n'
        result = scan(code)
        self.assertIn("JWT-002", rule_ids(result))

    def test_ignore_expiration_detected(self):
        code = 'jwt.decode(token, key, ignore_expiration=True)\n'
        result = scan(code)
        self.assertIn("JWT-005", rule_ids(result))

    def test_valid_jwt_usage_not_flagged(self):
        code = 'payload = jwt.decode(token, SECRET, algorithms=["HS256"])\n'
        result = scan(code)
        # JWT-001 should not fire (no 'none' algorithm)
        self.assertNotIn("JWT-001", rule_ids(result))
        self.assertNotIn("JWT-002", rule_ids(result))
        self.assertNotIn("JWT-005", rule_ids(result))

    def test_jwt_rules_are_critical_severity(self):
        """JWT-001 and JWT-002 are critical."""
        code = 'jwt.decode(t, k, algorithms="none")\n'
        result = scan(code)
        jwt_findings = [f for f in result.findings if f.rule_id == "JWT-001"]
        if jwt_findings:
            self.assertEqual(jwt_findings[0].severity, Severity.CRITICAL)


# ─────────────────────────────────────────────────────────────────────────────
# Security headers
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHeaders(unittest.TestCase):

    def test_xframe_allow_detected(self):
        code = 'response.headers["X-Frame-Options"] = "ALLOW"\n'
        result = scan(code)
        self.assertIn("HDR-001", rule_ids(result))

    def test_xframe_deny_not_flagged(self):
        code = 'response.headers["X-Frame-Options"] = "DENY"\n'
        result = scan(code)
        self.assertNotIn("HDR-001", rule_ids(result))

    def test_cors_credentials_true_detected(self):
        code = '"Access-Control-Allow-Credentials": "true"\n'
        result = scan(code)
        self.assertIn("HDR-002", rule_ids(result))

    def test_django_hsts_zero_detected(self):
        code = 'SECURE_HSTS_SECONDS = 0\n'
        result = scan(code)
        self.assertIn("HDR-004", rule_ids(result))

    def test_django_ssl_redirect_false_detected(self):
        code = 'SECURE_SSL_REDIRECT = False\n'
        result = scan(code)
        self.assertIn("HDR-005", rule_ids(result))

    def test_helmet_hsts_false_detected(self):
        code = 'app.use(helmet({ hsts: false }));\n'
        result = scan(code, filename="app.js")
        self.assertIn("HDR-003", rule_ids(result))

    def test_helmet_hsts_false_not_on_python(self):
        code = 'hsts: false\n'
        result = scan(code, filename="app.py")
        self.assertNotIn("HDR-003", rule_ids(result))


# ─────────────────────────────────────────────────────────────────────────────
# Confidence scores
# ─────────────────────────────────────────────────────────────────────────────

class TestConfidenceScores(unittest.TestCase):

    def test_confidence_map_non_empty(self):
        self.assertGreater(len(CONFIDENCE_MAP), 0)

    def test_known_low_confidence_rules_in_map(self):
        self.assertIn("AUTH-020", CONFIDENCE_MAP)
        self.assertEqual(CONFIDENCE_MAP["AUTH-020"], "LOW")

    def test_known_medium_confidence_rules_in_map(self):
        self.assertIn("SEC-013", CONFIDENCE_MAP)
        self.assertEqual(CONFIDENCE_MAP["SEC-013"], "MEDIUM")

    def test_stripe_key_has_high_confidence(self):
        """Stripe key pattern is specific — should not be in CONFIDENCE_MAP (defaults HIGH)."""
        self.assertNotIn("SEC-001", CONFIDENCE_MAP)

    def test_finding_has_confidence_field(self):
        code = 'api_key = "abcdef1234567890abcdef"\n'
        result = scan(code)
        for f in result.findings:
            self.assertIn(f.confidence, ("HIGH", "MEDIUM", "LOW"),
                          f"{f.rule_id} has invalid confidence '{f.confidence}'")

    def test_confidence_in_json_output(self):
        code = 'api_key = "abcdef1234567890abcdef"\n'
        data = scan_json(code)
        for f in data.get("findings", []):
            self.assertIn("confidence", f)
            self.assertIn(f["confidence"], ("HIGH", "MEDIUM", "LOW"))

    def test_high_confidence_not_shown_in_console(self):
        """HIGH confidence findings don't show the confidence label in console."""
        code = 'api_key = "abcdef1234567890abcdef"\n'
        result = scan(code)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_results(result)
        # HIGH confidence findings should not show [HIGH CONFIDENCE]
        high_conf_findings = [f for f in result.findings if f.confidence == "HIGH"]
        if high_conf_findings:
            self.assertNotIn("[HIGH CONFIDENCE]", buf.getvalue())

    def test_medium_confidence_shown_in_console(self):
        """MEDIUM confidence findings show [MEDIUM CONFIDENCE] label."""
        code = 'api_key = "abcdef1234567890abcdef"\n'
        result = scan(code)
        med_findings = [f for f in result.findings if f.confidence == "MEDIUM"]
        if med_findings:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                print_results(result)
            self.assertIn("MEDIUM CONFIDENCE", buf.getvalue())


# ─────────────────────────────────────────────────────────────────────────────
# VS Code output format
# ─────────────────────────────────────────────────────────────────────────────

class TestVSCodeOutput(unittest.TestCase):

    def test_vscode_output_format(self):
        """Each finding produces a file:line: severity: message line."""
        code = 'api_key = "abcdef1234567890abcdef"\n'
        output = scan_vscode(code)
        lines = [l for l in output.strip().splitlines() if l]
        if lines:
            # Should match: path:line: error|warning: [RULE] message
            import re
            pattern = re.compile(r'^.+:\d+:\s+(error|warning):\s+\[.+\].+$')
            for line in lines:
                self.assertRegex(line, pattern, f"Line does not match VS Code format: {line!r}")

    def test_vscode_no_json_in_output(self):
        code = 'api_key = "abcdef1234567890abcdef"\n'
        output = scan_vscode(code)
        self.assertFalse(output.startswith("{"), "VS Code output should not be JSON")

    def test_vscode_error_for_critical(self):
        code = 'cursor.execute(f"SELECT * FROM t WHERE id={x}")\n'
        output = scan_vscode(code)
        self.assertIn("error:", output)

    def test_vscode_empty_when_no_findings(self):
        output = scan_vscode("x = 1\n")
        self.assertEqual(output.strip(), "")


# ─────────────────────────────────────────────────────────────────────────────
# VS Code installer
# ─────────────────────────────────────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from install_vscode import install, uninstall


class TestVSCodeInstaller(unittest.TestCase):

    def _make_project(self):
        return tempfile.mkdtemp()

    def test_install_creates_tasks_json(self):
        project = self._make_project()
        result = install(project)
        self.assertTrue(result)
        tasks_file = Path(project) / ".vscode" / "tasks.json"
        self.assertTrue(tasks_file.exists())

    def test_tasks_json_is_valid_json(self):
        project = self._make_project()
        install(project)
        tasks_file = Path(project) / ".vscode" / "tasks.json"
        data = json.loads(tasks_file.read_text(encoding="utf-8"))
        self.assertIn("tasks", data)
        self.assertGreater(len(data["tasks"]), 0)

    def test_tasks_contain_vibe_label(self):
        project = self._make_project()
        install(project)
        data = json.loads((Path(project) / ".vscode" / "tasks.json").read_text(encoding="utf-8"))
        labels = [t["label"] for t in data["tasks"]]
        self.assertTrue(any("Vibe" in l for l in labels))

    def test_idempotent_install(self):
        project = self._make_project()
        install(project)
        result = install(project)   # second install
        self.assertTrue(result)

    def test_install_fails_on_nonexistent_path(self):
        result = install("/nonexistent/path/that/does/not/exist")
        self.assertFalse(result)

    def test_uninstall_removes_vibe_tasks(self):
        project = self._make_project()
        install(project)
        result = uninstall(project)
        self.assertTrue(result)
        tasks_file = Path(project) / ".vscode" / "tasks.json"
        self.assertFalse(tasks_file.exists())

    def test_uninstall_preserves_other_tasks(self):
        project = self._make_project()
        vscode_dir = Path(project) / ".vscode"
        vscode_dir.mkdir()
        # Start with an existing non-Vibe task
        existing = {"version": "2.0.0", "tasks": [
            {"label": "Other: Build", "type": "shell", "command": "make"}
        ]}
        tasks_file = vscode_dir / "tasks.json"
        tasks_file.write_text(json.dumps(existing), encoding="utf-8")
        # Merge Vibe tasks in
        install(project, force=True)
        # Uninstall — should leave Other: Build intact
        uninstall(project)
        # File should still exist (Other: Build remains)
        self.assertTrue(tasks_file.exists(), "tasks.json should survive if other tasks remain")
        data = json.loads(tasks_file.read_text(encoding="utf-8"))
        labels = [t["label"] for t in data["tasks"]]
        self.assertIn("Other: Build", labels)
        self.assertFalse(any("Vibe" in l for l in labels))

    def test_problem_matcher_pattern_in_tasks(self):
        """The problem matcher regex must match our --vscode output format."""
        import re
        project = self._make_project()
        install(project)
        data = json.loads((Path(project) / ".vscode" / "tasks.json").read_text(encoding="utf-8"))
        pm = data["tasks"][0]["problemMatcher"]
        pattern = pm["pattern"]["regexp"]
        # Test against a real vscode output line
        sample = "src/app.py:5: error: [SEC-013] Hardcoded API key"
        self.assertRegex(sample, re.compile(pattern))


# ─────────────────────────────────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from generate_report import generate_html_report


def _mock_results(critical=0, high=0, grade="A", findings=None):
    return {
        "scan_date": "2026-04-12T00:00:00",
        "project_path": "/test/project",
        "security_findings": {
            "grade": grade,
            "critical": critical,
            "high": high,
            "medium": 0,
            "low": 0,
            "total_findings": critical + high,
            "suppressed_by_baseline": 0,
            "findings": findings or [],
        },
        "dependency_findings": {"total_findings": 0, "findings": []},
        "project_info": {"project_type": "python", "languages": ["Python"],
                         "frameworks": [], "databases": [], "cloud_services": [],
                         "ai_tool_indicators": []},
        "semgrep_findings": {"available": False},
    }


class TestHTMLReport(unittest.TestCase):

    def test_html_report_is_html(self):
        html = generate_html_report(_mock_results())
        self.assertTrue(html.strip().startswith("<!DOCTYPE html"))

    def test_html_report_contains_grade(self):
        html = generate_html_report(_mock_results(grade="F", critical=1))
        self.assertIn(">F<", html)

    def test_html_report_contains_critical_count(self):
        html = generate_html_report(_mock_results(critical=3, grade="F"))
        self.assertIn("3", html)

    def test_html_report_escapes_xss(self):
        """Project path with HTML characters should be escaped."""
        results = _mock_results()
        results["project_path"] = '<script>alert(1)</script>'
        html = generate_html_report(results)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_report_shows_finding_details(self):
        finding = {
            "rule_id": "SEC-013",
            "severity": "CRITICAL",
            "category": "Secrets",
            "description": "Hardcoded API key",
            "file": "app.py",
            "line": 5,
            "snippet": 'api_key = "****"',
            "remediation": "Use env var",
            "cwe_id": "CWE-798",
            "cwe_name": "Use of Hard-coded Credentials",
            "owasp": "A02:2021",
            "fix_hint": "api_key = os.environ.get('API_KEY')",
            "confidence": "MEDIUM",
        }
        results = _mock_results(critical=1, grade="F", findings=[finding])
        html = generate_html_report(results)
        self.assertIn("SEC-013", html)
        self.assertIn("Hardcoded API key", html)
        self.assertIn("app.py", html)

    def test_html_report_clean_project(self):
        html = generate_html_report(_mock_results(grade="A"))
        self.assertIn(">A<", html)
        self.assertIn("No security findings", html)


# ─────────────────────────────────────────────────────────────────────────────
# Git history scanner (unit tests — no real git needed)
# ─────────────────────────────────────────────────────────────────────────────

from scan_git_history import GitHistoryScanner, HistoryFinding


class TestGitHistoryScanner(unittest.TestCase):

    def _scanner(self, repo_path="/fake"):
        s = GitHistoryScanner(repo_path, max_commits=10)
        s._seen_fingerprints = set()
        s.findings = []
        return s

    def test_check_line_detects_stripe_key(self):
        s = self._scanner()
        s._check_line(
            'api_key = "sk-live-abcdefghijklmnopqrstuvwxyz1234"',
            "config.py", "abc123", "2026-01-01", "dev", "add config"
        )
        self.assertTrue(any(f.rule_id.startswith("SEC-") for f in s.findings))

    def test_check_line_detects_aws_key(self):
        s = self._scanner()
        s._check_line('aws_key = "AKIAIOSFODNN7EXAMPLE"',
                      "creds.py", "def456", "2026-01-01", "dev", "init")
        self.assertTrue(any(f.rule_id == "SEC-003" for f in s.findings))

    def test_check_line_no_secret_no_finding(self):
        s = self._scanner()
        s._check_line('x = 1 + 2', "app.py", "abc", "2026-01-01", "dev", "math")
        self.assertEqual(s.findings, [])

    def test_deduplicated_findings(self):
        """Same secret on same file+commit should not produce duplicate findings."""
        s = self._scanner()
        # Use an AWS key which matches exactly one rule (SEC-003)
        line = '"AKIAIOSFODNN7EXAMPLE"'
        s._check_line(line, "c.py", "aaa", "2026-01-01", "dev", "a")
        count_after_first = len(s.findings)
        s._check_line(line, "c.py", "aaa", "2026-01-01", "dev", "a")  # identical call
        self.assertEqual(len(s.findings), count_after_first,
                         "Identical finding should be deduplicated")

    def test_history_finding_has_all_fields(self):
        s = self._scanner()
        s._check_line('api_key = "AKIAIOSFODNN7EXAMPLE"',
                      "creds.py", "abc123", "2026-01-01", "Alice", "add key")
        if s.findings:
            f = s.findings[0]
            self.assertEqual(f.commit_hash, "abc123")
            self.assertEqual(f.commit_author, "Alice")
            self.assertEqual(f.file_path, "creds.py")

    def test_not_git_repo_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            scanner = GitHistoryScanner(d)
            findings = scanner.scan()
        self.assertEqual(findings, [])

    def test_finding_fingerprint_stable(self):
        f1 = HistoryFinding("SEC-003", "AWS key", "abc", "2026-01-01",
                            "dev", "msg", "f.py", 'api = "AKIAIOSFODNN7"', False)
        f2 = HistoryFinding("SEC-003", "AWS key", "xyz", "2026-02-01",
                            "other", "other", "f.py", 'api = "AKIAIOSFODNN7"', True)
        self.assertEqual(f1.fingerprint(), f2.fingerprint())


if __name__ == "__main__":
    unittest.main()
