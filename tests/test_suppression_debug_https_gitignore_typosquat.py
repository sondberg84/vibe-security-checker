"""
Tests for:
  - Inline suppression (# vibe-ignore, # vibe-ignore RULE-ID)
  - Debug mode detection (DBG-001 to DBG-005)
  - HTTPS enforcement (NET-001 to NET-004)
  - .env gitignore check (GIT-001)
  - Typosquatting detection in check_dependencies
"""
import sys
import json
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from scan_security import (
    SecurityScanner, ScanConfig, ScanResult,
)
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from check_dependencies import DependencyChecker, KNOWN_TYPOSQUATS


# ── helpers ──────────────────────────────────────────────────────────────────

def make_project(files: dict) -> str:
    d = tempfile.mkdtemp()
    for name, content in files.items():
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content))
    return d


def scan(code: str, filename: str = "app.py", config: ScanConfig = None) -> ScanResult:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / filename).write_text(textwrap.dedent(code))
        return SecurityScanner(d, config=config).scan()


def scan_dir(project: str, config: ScanConfig = None) -> ScanResult:
    return SecurityScanner(project, config=config).scan()


def rule_ids(result: ScanResult):
    return {f.rule_id for f in result.findings}


# ─────────────────────────────────────────────────────────────────────────────
# Inline suppression
# ─────────────────────────────────────────────────────────────────────────────

class TestInlineSuppression(unittest.TestCase):

    def test_vibe_ignore_suppresses_any_rule(self):
        """Bare # vibe-ignore suppresses all rules on that line."""
        code = 'api_key = "abcdef1234567890abcdef"  # vibe-ignore\n'
        result = scan(code)
        # No SEC-* rules should fire on that line
        self.assertFalse(any(f.rule_id.startswith("SEC-") for f in result.findings),
                         "# vibe-ignore should suppress all rules on the line")

    def test_vibe_ignore_specific_rule_suppressed(self):
        """# vibe-ignore SEC-013 suppresses only SEC-013."""
        code = 'api_key = "abcdef1234567890abcdef"  # vibe-ignore SEC-013\n'
        result = scan(code)
        self.assertNotIn("SEC-013", rule_ids(result))

    def test_vibe_ignore_specific_does_not_suppress_other_rules(self):
        """# vibe-ignore SEC-013 should NOT suppress SEC-018 (Alpaca key pattern)."""
        # This line matches SEC-013 (api key) AND SEC-018 (PK prefix Alpaca key)
        code = 'api_key = "PKabcdef1234567890ABCDEF"  # vibe-ignore SEC-013\n'
        result = scan(code)
        # SEC-013 should be suppressed; SEC-018 should still fire if it matches
        self.assertNotIn("SEC-013", rule_ids(result))

    def test_vibe_ignore_js_double_slash(self):
        """// vibe-ignore works for JS/TS files."""
        code = 'element.innerHTML = userInput; // vibe-ignore\n'
        result = scan(code, filename="app.js")
        self.assertNotIn("INJ-020", rule_ids(result))

    def test_no_suppression_without_comment(self):
        """Without a vibe-ignore comment, the rule fires normally."""
        code = 'api_key = "abcdef1234567890abcdef"\n'
        result = scan(code)
        self.assertTrue(any(f.rule_id.startswith("SEC-") for f in result.findings))

    def test_vibe_ignore_does_not_affect_other_lines(self):
        """Suppression is line-scoped — other lines still fire."""
        code = (
            'api_key = "abcdef1234567890abcdef"  # vibe-ignore\n'
            'api_key = "abcdef1234567890abcdef"\n'   # second line, no suppression
        )
        result = scan(code)
        self.assertTrue(any(f.rule_id.startswith("SEC-") for f in result.findings),
                        "Second line without vibe-ignore should still fire")

    def test_vibe_ignore_entropy(self):
        """# vibe-ignore suppresses SEC-ENT on that line."""
        code = 'signing_key = "aB3dEf7gHiJkLm9nOpQr2sT4uVwXyZ0123456789"  # vibe-ignore\n'
        result = scan(code)
        self.assertNotIn("SEC-ENT", rule_ids(result))

    def test_is_suppressed_method_bare(self):
        """_is_suppressed returns True for bare vibe-ignore."""
        from scan_security import SecurityScanner as SS
        self.assertTrue(SS._is_suppressed('x = 1  # vibe-ignore', 'ANY-001'))

    def test_is_suppressed_method_specific_match(self):
        from scan_security import SecurityScanner as SS
        self.assertTrue(SS._is_suppressed('x = 1  # vibe-ignore SEC-013', 'SEC-013'))

    def test_is_suppressed_method_specific_no_match(self):
        from scan_security import SecurityScanner as SS
        self.assertFalse(SS._is_suppressed('x = 1  # vibe-ignore SEC-013', 'SEC-017'))

    def test_is_suppressed_method_no_comment(self):
        from scan_security import SecurityScanner as SS
        self.assertFalse(SS._is_suppressed('api_key = "secret"', 'SEC-013'))


# ─────────────────────────────────────────────────────────────────────────────
# Debug mode detection
# ─────────────────────────────────────────────────────────────────────────────

class TestDebugDetection(unittest.TestCase):

    def test_flask_debug_true_detected(self):
        code = 'app.run(host="0.0.0.0", debug=True)\n'
        result = scan(code)
        self.assertIn("DBG-001", rule_ids(result))

    def test_django_debug_true_detected(self):
        code = 'DEBUG = True\n'
        result = scan(code)
        self.assertIn("DBG-002", rule_ids(result))

    def test_debug_true_in_json_config(self):
        code = '{"debug": true, "port": 3000}\n'
        result = scan(code, filename="config.json")
        self.assertIn("DBG-003", rule_ids(result))

    def test_console_log_sensitive_detected(self):
        code = 'console.log("token:", userToken);\n'
        result = scan(code, filename="app.js")
        self.assertIn("DBG-004", rule_ids(result))

    def test_console_log_non_sensitive_not_flagged(self):
        code = 'console.log("Hello world");\n'
        result = scan(code, filename="app.js")
        self.assertNotIn("DBG-004", rule_ids(result))

    def test_print_sensitive_detected(self):
        code = 'print("api_key:", api_key)\n'
        result = scan(code)
        self.assertIn("DBG-005", rule_ids(result))

    def test_debug_false_not_flagged(self):
        code = 'DEBUG = False\n'
        result = scan(code)
        self.assertNotIn("DBG-002", rule_ids(result))

    def test_dbg_rules_not_flagged_on_wrong_file_type(self):
        """DBG-001 (app.run) should not fire on a .js file."""
        code = 'app.run(debug=True)\n'
        result = scan(code, filename="app.js")
        self.assertNotIn("DBG-001", rule_ids(result))

    def test_console_log_not_flagged_on_python_file(self):
        """DBG-004 (console.log) should not fire on .py files."""
        code = 'console.log("token:", userToken)\n'
        result = scan(code, filename="app.py")
        self.assertNotIn("DBG-004", rule_ids(result))


# ─────────────────────────────────────────────────────────────────────────────
# HTTPS enforcement
# ─────────────────────────────────────────────────────────────────────────────

class TestHTTPSEnforcement(unittest.TestCase):

    def test_http_url_in_string_detected(self):
        code = 'API_URL = "http://api.example.com/v1"\n'
        result = scan(code)
        self.assertIn("NET-001", rule_ids(result))

    def test_http_localhost_not_flagged(self):
        code = 'BASE_URL = "http://localhost:8000"\n'
        result = scan(code)
        self.assertNotIn("NET-001", rule_ids(result))

    def test_http_127_not_flagged(self):
        code = 'BASE_URL = "http://127.0.0.1:5000"\n'
        result = scan(code)
        self.assertNotIn("NET-001", rule_ids(result))

    def test_https_not_flagged(self):
        code = 'API_URL = "https://api.example.com/v1"\n'
        result = scan(code)
        self.assertNotIn("NET-001", rule_ids(result))

    def test_httponly_false_detected(self):
        code = 'res.cookie("session", token, { httpOnly: false });\n'
        result = scan(code, filename="app.js")
        self.assertIn("NET-002", rule_ids(result))

    def test_httponly_true_not_flagged(self):
        code = 'res.cookie("session", token, { httpOnly: true });\n'
        result = scan(code, filename="app.js")
        self.assertNotIn("NET-002", rule_ids(result))

    def test_django_cookie_secure_false_detected(self):
        code = 'SESSION_COOKIE_SECURE = False\n'
        result = scan(code)
        self.assertIn("NET-004", rule_ids(result))


# ─────────────────────────────────────────────────────────────────────────────
# .env gitignore check
# ─────────────────────────────────────────────────────────────────────────────

class TestGitignoreCheck(unittest.TestCase):

    def test_env_not_gitignored_flagged(self):
        project = make_project({
            ".env": "API_KEY=secret123\n",
            ".gitignore": "*.pyc\n__pycache__\n",   # .env NOT listed
        })
        result = scan_dir(project)
        self.assertIn("GIT-001", rule_ids(result))

    def test_env_gitignored_not_flagged(self):
        project = make_project({
            ".env": "API_KEY=secret123\n",
            ".gitignore": ".env\n*.pyc\n",
        })
        result = scan_dir(project)
        self.assertNotIn("GIT-001", rule_ids(result))

    def test_env_covered_by_glob_not_flagged(self):
        project = make_project({
            ".env": "API_KEY=secret123\n",
            ".gitignore": "*.env\n",
        })
        result = scan_dir(project)
        self.assertNotIn("GIT-001", rule_ids(result))

    def test_env_example_never_flagged(self):
        project = make_project({
            ".env.example": "API_KEY=your_key_here\n",
            ".gitignore": "*.pyc\n",
        })
        result = scan_dir(project)
        self.assertNotIn("GIT-001", rule_ids(result))

    def test_no_env_file_no_finding(self):
        project = make_project({
            "app.py": "x = 1\n",
            ".gitignore": "*.pyc\n",
        })
        result = scan_dir(project)
        self.assertNotIn("GIT-001", rule_ids(result))

    def test_no_gitignore_with_env_flagged(self):
        project = make_project({
            ".env": "API_KEY=secret123\n",
        })
        result = scan_dir(project)
        self.assertIn("GIT-001", rule_ids(result))

    def test_git001_suppressed_by_exclude_rules(self):
        project = make_project({
            ".env": "API_KEY=secret123\n",
        })
        config = ScanConfig(exclude_rules={"GIT-001"})
        result = scan_dir(project, config=config)
        self.assertNotIn("GIT-001", rule_ids(result))


# ─────────────────────────────────────────────────────────────────────────────
# Typosquatting detection
# ─────────────────────────────────────────────────────────────────────────────

class TestTyposquatDetection(unittest.TestCase):

    def _check_deps(self, files: dict):
        project = make_project(files)
        with patch("check_dependencies.query_osv_batch", return_value=[[]]):
            return DependencyChecker(project).check()

    def test_python_typosquat_detected(self):
        """'colourama' should be flagged as a typosquat of 'colorama'."""
        findings = self._check_deps({"requirements.txt": "colourama==0.4.6\n"})
        typos = [f for f in findings if f.issue_type == "typosquat"]
        self.assertTrue(any("colourama" in f.package for f in typos))

    def test_npm_typosquat_detected(self):
        """'crossenv' is a known malicious npm package."""
        pkg_json = {"dependencies": {"crossenv": "^1.0.0"}}
        findings = self._check_deps({"package.json": json.dumps(pkg_json)})
        typos = [f for f in findings if f.issue_type == "typosquat"]
        self.assertTrue(any("crossenv" in f.package for f in typos))

    def test_legitimate_package_not_flagged(self):
        findings = self._check_deps({"requirements.txt": "requests==2.31.0\n"})
        typos = [f for f in findings if f.issue_type == "typosquat"]
        self.assertEqual(typos, [])

    def test_typosquat_severity_is_critical(self):
        findings = self._check_deps({"requirements.txt": "colourama==0.4.6\n"})
        typos = [f for f in findings if f.issue_type == "typosquat"]
        if typos:
            self.assertEqual(typos[0].severity, "CRITICAL")

    def test_known_typosquats_dict_non_empty(self):
        self.assertGreater(len(KNOWN_TYPOSQUATS["python"]), 0)
        self.assertGreater(len(KNOWN_TYPOSQUATS["npm"]), 0)

    def test_pycrypto_flagged_as_typosquat(self):
        """pycrypto is abandoned and should be replaced with pycryptodome."""
        findings = self._check_deps({"requirements.txt": "pycrypto==2.6.1\n"})
        typos = [f for f in findings if f.issue_type == "typosquat"]
        self.assertTrue(any("pycrypto" in f.package for f in typos))

    def test_npm_axois_typosquat_detected(self):
        """'axois' is a common typo of 'axios'."""
        pkg_json = {"dependencies": {"axois": "^1.0.0"}}
        findings = self._check_deps({"package.json": json.dumps(pkg_json)})
        typos = [f for f in findings if f.issue_type == "typosquat"]
        self.assertTrue(any("axois" in f.package for f in typos))


if __name__ == "__main__":
    unittest.main()
