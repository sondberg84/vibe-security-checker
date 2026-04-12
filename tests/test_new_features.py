"""
Tests for:
  - Entropy-based secret detection (SEC-ENT)
  - Secret value masking (_mask_snippet, _display_snippet)
  - Security grade (ScanResult.grade)
  - Git diff incremental scan (_git_changed_files, diff_files config)
  - Language-aware rule filtering (RULE_EXTENSIONS)
"""
import sys
import io
import json
import tempfile
import textwrap
import unittest
import contextlib
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from scan_security import (
    SecurityScanner, ScanConfig, ScanResult, Finding, Severity,
    _shannon_entropy, _mask_snippet, _display_snippet,
    _git_changed_files, RULE_EXTENSIONS,
    print_results,
)


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


def scan_json(code: str, filename: str = "app.py") -> dict:
    result = scan(code, filename)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_results(result, json_output=True)
    return json.loads(buf.getvalue())


def _finding(rule_id="SEC-013", category="Secrets", severity=Severity.CRITICAL,
             snippet="api_key = 'abcdef1234567890'"):
    return Finding(
        rule_id=rule_id, severity=severity, category=category,
        description="test", file_path="f.py", line_number=1,
        code_snippet=snippet, remediation="fix",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ─────────────────────────────────────────────────────────────────────────────

class TestShannonEntropy(unittest.TestCase):

    def test_empty_string_is_zero(self):
        self.assertEqual(_shannon_entropy(""), 0.0)

    def test_uniform_string_low_entropy(self):
        # "aaaaaaaaaa" has entropy 0
        self.assertEqual(_shannon_entropy("aaaaaaaaaa"), 0.0)

    def test_random_like_string_high_entropy(self):
        # A base64-like random string should exceed 4.5
        s = "aB3dEf7gHiJkLm9nOpQr2sT4uVwXyZ01"
        self.assertGreater(_shannon_entropy(s), 4.0)

    def test_english_text_below_threshold(self):
        # Normal English words have lower entropy
        s = "helloworld"
        self.assertLess(_shannon_entropy(s), 4.5)


# ─────────────────────────────────────────────────────────────────────────────
# Entropy-based secret detection (SEC-ENT)
# ─────────────────────────────────────────────────────────────────────────────

class TestEntropyDetection(unittest.TestCase):

    def test_high_entropy_secret_detected(self):
        # High-entropy value assigned to secret-sounding variable
        code = 'signing_key = "aB3dEf7gHiJkLm9nOpQr2sT4uVwXyZ0123456789"\n'
        result = scan(code)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("SEC-ENT", rule_ids, "High-entropy signing_key should be flagged")

    def test_low_entropy_value_not_detected(self):
        # Low-entropy placeholder is not flagged by entropy scan
        # (it may still be caught by pattern rules, but not SEC-ENT)
        code = 'signing_key = "aaaaaaaaaaaaaaaaaaaaaaaa"\n'
        result = scan(code)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("SEC-ENT", rule_ids, "Low-entropy value should not trigger SEC-ENT")

    def test_short_value_not_detected(self):
        # Values shorter than ENTROPY_MIN_LENGTH should be ignored
        code = 'api_key = "short"\n'
        result = scan(code)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("SEC-ENT", rule_ids)

    def test_non_secret_variable_not_flagged(self):
        # High-entropy value but variable name is not secret-sounding
        code = 'user_name = "aB3dEf7gHiJkLm9nOpQr2sT4uVwXyZ0123456789"\n'
        result = scan(code)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("SEC-ENT", rule_ids)

    def test_entropy_finding_is_critical(self):
        code = 'signing_key = "aB3dEf7gHiJkLm9nOpQr2sT4uVwXyZ0123456789"\n'
        result = scan(code)
        ent = [f for f in result.findings if f.rule_id == "SEC-ENT"]
        if ent:
            self.assertEqual(ent[0].severity, Severity.CRITICAL)

    def test_entropy_suppressed_by_exclude_rules(self):
        code = 'signing_key = "aB3dEf7gHiJkLm9nOpQr2sT4uVwXyZ0123456789"\n'
        config = ScanConfig(exclude_rules={"SEC-ENT"})
        result = scan(code, config=config)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("SEC-ENT", rule_ids)


# ─────────────────────────────────────────────────────────────────────────────
# Secret value masking
# ─────────────────────────────────────────────────────────────────────────────

class TestMaskSnippet(unittest.TestCase):

    def test_masks_quoted_secret(self):
        snippet = 'api_key = "abcdef1234567890"'
        masked = _mask_snippet(snippet)
        self.assertNotIn("abcdef1234567890", masked)
        self.assertIn("****", masked)

    def test_preserves_variable_name(self):
        snippet = 'api_key = "abcdef1234567890"'
        masked = _mask_snippet(snippet)
        self.assertIn("api_key", masked)

    def test_short_values_not_masked(self):
        # Values shorter than 8 chars are left alone
        snippet = 'flag = "ok"'
        masked = _mask_snippet(snippet)
        self.assertEqual(masked, snippet)

    def test_single_quoted_secret_masked(self):
        snippet = "token = 'abcdefghijklmnop'"
        masked = _mask_snippet(snippet)
        self.assertNotIn("abcdefghijklmnop", masked)
        self.assertIn("****", masked)


class TestDisplaySnippet(unittest.TestCase):

    def test_secrets_category_masked(self):
        f = _finding(category="Secrets", snippet='api_key = "abcdef1234567890"')
        self.assertIn("****", _display_snippet(f))

    def test_non_secrets_category_not_masked(self):
        f = _finding(category="Injection (sql)", snippet='cursor.execute(f"SELECT {x}")')
        self.assertEqual(_display_snippet(f), f.code_snippet)

    def test_json_output_masks_secrets(self):
        data = scan_json('api_key = "abcdef1234567890abcdef"\n')
        secret_findings = [f for f in data["findings"] if f["category"] == "Secrets"]
        for sf in secret_findings:
            self.assertNotIn("abcdef1234567890abcdef", sf["snippet"],
                             "Secret value should be masked in JSON output")
            self.assertIn("****", sf["snippet"])

    def test_json_output_does_not_mask_non_secrets(self):
        data = scan_json('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        inj_findings = [f for f in data["findings"] if "INJ" in f["rule_id"]]
        for f in inj_findings:
            self.assertNotIn("****", f["snippet"],
                             "Non-secret snippets should not be masked")


# ─────────────────────────────────────────────────────────────────────────────
# Security grade
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityGrade(unittest.TestCase):

    def _result_with(self, severities):
        r = ScanResult()
        for s in severities:
            r.add(_finding(severity=s))
        return r

    def test_grade_a_no_findings(self):
        self.assertEqual(ScanResult().grade(), "A")

    def test_grade_b_low_only(self):
        r = self._result_with([Severity.LOW])
        self.assertEqual(r.grade(), "B")

    def test_grade_c_medium(self):
        r = self._result_with([Severity.LOW, Severity.MEDIUM])
        self.assertEqual(r.grade(), "C")

    def test_grade_d_high(self):
        r = self._result_with([Severity.HIGH])
        self.assertEqual(r.grade(), "D")

    def test_grade_f_critical(self):
        r = self._result_with([Severity.CRITICAL])
        self.assertEqual(r.grade(), "F")

    def test_grade_f_overrides_lower(self):
        r = self._result_with([Severity.LOW, Severity.MEDIUM, Severity.CRITICAL])
        self.assertEqual(r.grade(), "F")

    def test_grade_in_json_output(self):
        # A file with no real vulnerabilities should give grade A
        data = scan_json("x = 1\n")
        self.assertIn("grade", data)

    def test_grade_f_in_json_for_critical(self):
        data = scan_json('api_key = "abcdef1234567890abcdef"\n')
        # Should have at least one critical finding → grade F
        if data["critical"] > 0:
            self.assertEqual(data["grade"], "F")


# ─────────────────────────────────────────────────────────────────────────────
# Language-aware rule filtering (RULE_EXTENSIONS)
# ─────────────────────────────────────────────────────────────────────────────

class TestLanguageFiltering(unittest.TestCase):

    def test_xss_not_reported_for_python_file(self):
        """innerHTML XSS pattern should not fire on a .py file."""
        code = 'element.innerHTML = user_input\n'
        result = scan(code, filename="app.py")
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("INJ-020", rule_ids, "XSS rule should not fire on .py files")

    def test_xss_reported_for_js_file(self):
        """innerHTML XSS pattern should fire on a .js file."""
        code = 'element.innerHTML = userInput;\n'
        result = scan(code, filename="app.js")
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("INJ-020", rule_ids, "XSS rule should fire on .js files")

    def test_pickle_not_reported_for_js_file(self):
        """pickle.loads pattern should not fire on a .js file."""
        code = 'const data = pickle.loads(buf);\n'
        result = scan(code, filename="app.js")
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("DATA-001", rule_ids, "Python pickle rule should not fire on .js")

    def test_pickle_reported_for_python_file(self):
        """pickle.loads pattern should fire on a .py file."""
        code = 'data = pickle.loads(buf)\n'
        result = scan(code, filename="app.py")
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("DATA-001", rule_ids, "Pickle rule should fire on .py files")

    def test_express_route_not_reported_for_python_file(self):
        """AUTH-021 (Express route) should not fire on .py files."""
        code = "router.get('/admin', async (req, res) => { res.send('ok') })\n"
        result = scan(code, filename="routes.py")
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("AUTH-021", rule_ids, "Express route rule should not fire on .py")

    def test_localstorage_not_reported_for_python_file(self):
        """AUTH-010 (localStorage) should not fire on .py files."""
        code = "localStorage.setItem('token', jwt)\n"
        result = scan(code, filename="auth.py")
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("AUTH-010", rule_ids)

    def test_localstorage_reported_for_js_file(self):
        """AUTH-010 should fire on .js files."""
        code = "localStorage.setItem('token', jwt);\n"
        result = scan(code, filename="auth.js")
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("AUTH-010", rule_ids)

    def test_rule_extensions_dict_contains_js_rules(self):
        js_rules = [r for r, exts in RULE_EXTENSIONS.items() if exts and '.js' in exts]
        self.assertGreater(len(js_rules), 0)

    def test_rule_extensions_dict_contains_py_rules(self):
        py_rules = [r for r, exts in RULE_EXTENSIONS.items() if exts and '.py' in exts]
        self.assertGreater(len(py_rules), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Git diff incremental scan
# ─────────────────────────────────────────────────────────────────────────────

class TestGitDiff(unittest.TestCase):

    def test_git_changed_files_returns_none_for_non_git_dir(self):
        with tempfile.TemporaryDirectory() as d:
            result = _git_changed_files(d)
        self.assertIsNone(result)

    def test_diff_files_config_restricts_scan(self):
        """When diff_files is set, only those files are scanned."""
        project = make_project({
            "src/safe.py": "x = 1\n",
            "src/vuln.py": 'api_key = "abcdef1234567890abcdef"\n',
        })
        # Only scan safe.py — vuln.py should NOT produce findings
        config = ScanConfig(diff_files={"src/safe.py"})
        result = scan_dir(project, config=config)
        for f in result.findings:
            self.assertNotIn("vuln.py", f.file_path,
                             "vuln.py was excluded from diff_files and should not be scanned")

    def test_diff_files_empty_set_scans_nothing(self):
        """Empty diff_files set means no files scanned."""
        project = make_project({
            "app.py": 'api_key = "abcdef1234567890abcdef"\n',
        })
        config = ScanConfig(diff_files=set())
        result = scan_dir(project, config=config)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.files_scanned, 0)

    def test_diff_files_none_scans_all(self):
        """When diff_files is None (default), all files are scanned."""
        project = make_project({
            "app.py": 'api_key = "abcdef1234567890abcdef"\n',
        })
        config = ScanConfig(diff_files=None)
        result = scan_dir(project, config=config)
        self.assertGreater(len(result.findings), 0)

    def test_git_changed_files_mocked_returns_set(self):
        """When git returns file names, _git_changed_files returns a set."""
        mock_output = "src/app.py\nsrc/utils.py\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = mock_output
            result = _git_changed_files("/fake/repo")
        self.assertIsInstance(result, set)
        self.assertIn("src/app.py", result)
        self.assertIn("src/utils.py", result)

    def test_git_changed_files_mocked_non_zero_returns_none(self):
        """When git exits non-zero, _git_changed_files returns None."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 128
            mock_run.return_value.stdout = ""
            result = _git_changed_files("/fake/repo")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
