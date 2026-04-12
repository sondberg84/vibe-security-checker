"""
Tests for vibe-security-checker scanner.
Covers: true positive detection, false positive prevention, edge cases.
"""
import sys
import os
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

# Add scripts/ to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from scan_security import SecurityScanner, Severity


def scan_code(code: str, filename: str = "test.py") -> list:
    """Scan a string of code and return findings as dicts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        fpath = Path(tmpdir) / filename
        fpath.write_text(textwrap.dedent(code))
        scanner = SecurityScanner(tmpdir)
        result = scanner.scan()
        return [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.name,
                "line": f.line_number,
                "cwe_id": f.cwe_id,
                "cwe_name": f.cwe_name,
                "owasp": f.owasp,
            }
            for f in result.findings
        ]


def rule_ids(findings: list) -> set:
    return {f["rule_id"] for f in findings}


def finding_for(findings: list, rule_id: str) -> dict:
    return next((f for f in findings if f["rule_id"] == rule_id), {})


# ===========================================================================
# SECRETS
# ===========================================================================

class TestSecretsDetection(unittest.TestCase):

    def test_stripe_key_detected(self):
        findings = scan_code('key = "sk-live-abc123def456ghi789jkl012"')
        self.assertIn("SEC-001", rule_ids(findings))

    def test_aws_key_detected(self):
        findings = scan_code('key = "AKIAIOSFODNN7EXAMPLE"')
        self.assertIn("SEC-003", rule_ids(findings))

    def test_anthropic_key_detected(self):
        findings = scan_code('key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"')
        self.assertIn("SEC-019", rule_ids(findings))

    def test_alpaca_paper_key_detected(self):
        findings = scan_code('{"api_key": "PKBOU3FQF32OFN76UJQ5OFUAH4"}', filename="credentials.json")
        self.assertIn("SEC-018", rule_ids(findings))

    def test_alpaca_live_key_detected(self):
        findings = scan_code('{"api_key": "AKBOU3FQF32OFN76UJQ5OFUAH4"}', filename="credentials.json")
        self.assertIn("SEC-018", rule_ids(findings))

    def test_hardcoded_api_key_assignment(self):
        findings = scan_code('api_key = "abcdef1234567890abcdef"')
        self.assertIn("SEC-013", rule_ids(findings))

    def test_hardcoded_api_key_json(self):
        findings = scan_code('{"api_key": "abcdef1234567890abcdef"}', filename="config.json")
        self.assertIn("SEC-013", rule_ids(findings))

    def test_hardcoded_api_secret_json(self):
        findings = scan_code('{"api_secret": "abcdef1234567890abcdef"}', filename="config.json")
        self.assertIn("SEC-017", rule_ids(findings))

    def test_hardcoded_password(self):
        findings = scan_code('password = "supersecret"')
        self.assertIn("SEC-012", rule_ids(findings))

    def test_hardcoded_password_json(self):
        findings = scan_code('{"password": "supersecret"}', filename="config.json")
        self.assertIn("SEC-012", rule_ids(findings))

    def test_env_file_unquoted_secret(self):
        findings = scan_code("ALPACA_API_KEY=PKBOU3FQF32OFN76UJQ5OFUAH4", filename=".env")
        self.assertIn("SEC-021", rule_ids(findings))

    def test_env_var_reference_not_flagged(self):
        # os.environ.get() should NOT be flagged as a hardcoded secret
        findings = scan_code('api_key = os.environ.get("ALPACA_API_KEY", "")')
        self.assertNotIn("SEC-013", rule_ids(findings))

    def test_mongodb_connection_string(self):
        findings = scan_code('uri = "mongodb://admin:password@localhost:27017"')
        self.assertIn("SEC-014", rule_ids(findings))


# ===========================================================================
# INJECTION
# ===========================================================================

class TestInjectionDetection(unittest.TestCase):

    def test_sql_fstring_detected(self):
        findings = scan_code('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")')
        self.assertIn("INJ-002", rule_ids(findings))

    def test_sql_concatenation_detected(self):
        findings = scan_code('cursor.execute("SELECT * FROM users WHERE id = " + user_id)')
        self.assertIn("INJ-004", rule_ids(findings))

    def test_os_system_detected(self):
        findings = scan_code('os.system("ls " + user_input)')
        self.assertIn("INJ-010", rule_ids(findings))

    def test_subprocess_shell_true_detected(self):
        findings = scan_code('subprocess.run(cmd, shell=True)')
        self.assertIn("INJ-011", rule_ids(findings))

    def test_subprocess_concatenation_detected(self):
        findings = scan_code('subprocess.run("git " + user_branch)')
        self.assertIn("INJ-015", rule_ids(findings))

    def test_eval_user_input_detected(self):
        findings = scan_code('eval(request.data)')
        self.assertIn("INJ-012", rule_ids(findings))

    def test_inner_html_detected(self):
        findings = scan_code('element.innerHTML = userContent', filename="test.js")
        self.assertIn("INJ-020", rule_ids(findings))

    def test_path_traversal_detected(self):
        findings = scan_code('path = "../" + filename')
        self.assertIn("INJ-040", rule_ids(findings))

    def test_open_with_user_input_detected(self):
        findings = scan_code('open(request.args["file"])')
        self.assertIn("INJ-042", rule_ids(findings))


# ===========================================================================
# CRYPTOGRAPHY
# ===========================================================================

class TestCryptoDetection(unittest.TestCase):

    def test_md5_password_detected(self):
        findings = scan_code('h = hashlib.md5(password.encode())')
        self.assertIn("AUTH-001", rule_ids(findings))

    def test_insecure_random_token_detected(self):
        findings = scan_code('token = random.randint(0, 999999)  # for secret token')
        self.assertIn("CRYPTO-010", rule_ids(findings))

    def test_math_random_detected(self):
        # keyword must appear after Math.random() on the same line
        findings = scan_code('const x = Math.random() * 1000; // session token id', filename="test.js")
        self.assertIn("CRYPTO-011", rule_ids(findings))


# ===========================================================================
# FALSE POSITIVE PREVENTION
# ===========================================================================

class TestFalsePositives(unittest.TestCase):

    def test_trades_function_not_flagged_as_des(self):
        """Regression: 'des' inside '_read_trades()' was falsely flagged as DES encryption."""
        findings = scan_code(textwrap.dedent("""
            def _read_trades():
                pass

            def _read_all_trades(year=None):
                pass

            trades = _read_trades()
            todays_trades = _read_all_trades()
        """))
        self.assertNotIn("CRYPTO-001", rule_ids(findings))

    def test_des_encryption_still_detected(self):
        """Ensure real DES usage IS still caught after the word-boundary fix."""
        findings = scan_code('cipher = DES("mysecretkey")')
        self.assertIn("CRYPTO-001", rule_ids(findings))

    def test_empty_string_password_not_flagged(self):
        """Empty string password assignments are noise — skip them."""
        findings = scan_code('password = ""')
        # SEC-012 requires non-empty value between quotes
        sec012 = [f for f in findings if f["rule_id"] == "SEC-012"]
        self.assertEqual(len(sec012), 0)

    def test_env_var_api_key_not_flagged_as_unquoted_secret(self):
        """os.environ.get in a .env-style file should not trigger SEC-021."""
        findings = scan_code("# this is just a comment\nSOME_VAR=short", filename=".env")
        self.assertNotIn("SEC-021", rule_ids(findings))  # 'short' < 16 chars


# ===========================================================================
# CWE / OWASP MAPPING
# ===========================================================================

class TestCweMapping(unittest.TestCase):

    def test_sql_injection_has_cwe89(self):
        findings = scan_code('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")')
        f = finding_for(findings, "INJ-002")
        self.assertEqual(f.get("cwe_id"), "CWE-89")
        self.assertIn("SQL", f.get("cwe_name", ""))

    def test_hardcoded_secret_has_cwe798(self):
        findings = scan_code('api_key = "abcdef1234567890abcdef"')
        f = finding_for(findings, "SEC-013")
        self.assertEqual(f.get("cwe_id"), "CWE-798")

    def test_path_traversal_has_cwe22(self):
        findings = scan_code('path = "../" + filename')
        f = finding_for(findings, "INJ-040")
        self.assertEqual(f.get("cwe_id"), "CWE-22")

    def test_broken_crypto_has_cwe327(self):
        findings = scan_code('cipher = DES("key")')
        f = finding_for(findings, "CRYPTO-001")
        self.assertEqual(f.get("cwe_id"), "CWE-327")

    def test_owasp_category_populated(self):
        findings = scan_code('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")')
        f = finding_for(findings, "INJ-002")
        self.assertIn("A03:2021", f.get("owasp", ""))

    def test_all_findings_have_cwe(self):
        """Every finding that hits a mapped rule should have a CWE."""
        code = textwrap.dedent("""
            api_key = "abcdef1234567890abcdef"
            cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
            os.system("ls " + user_input)
            path = "../" + filename
        """)
        findings = scan_code(code)
        for f in findings:
            self.assertNotEqual(f.get("cwe_id", ""), "",
                msg=f"{f['rule_id']} is missing a CWE mapping")


if __name__ == "__main__":
    unittest.main()
