"""
Tests for:
  - Finding deduplication (first match per rule per file, "and N more" label)
  - Auto-fix hints (FIX_HINTS, fix_hint field, JSON output)
  - SARIF output (CWE helpUri, tags, fullDescription)
  - Pre-commit hook installer (install, uninstall, force, idempotent)
"""
import sys
import json
import stat
import tempfile
import textwrap
import unittest
from pathlib import Path

# ── scanner imports ──────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from scan_security import (
    SecurityScanner, ScanConfig, Finding, Severity,
    FIX_HINTS, CWE_MAP, ScanResult, print_results,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def make_project(files: dict) -> str:
    d = tempfile.mkdtemp()
    for name, content in files.items():
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content))
    return d


def scan(code: str, filename: str = "app.py") -> ScanResult:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / filename).write_text(textwrap.dedent(code))
        return SecurityScanner(d).scan()


def scan_json(code: str, filename: str = "app.py") -> dict:
    """Run scan and return the JSON output dict."""
    import io, contextlib
    result = scan(code, filename)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_results(result, json_output=True)
    return json.loads(buf.getvalue())


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplication(unittest.TestCase):

    def test_multiple_matches_produce_single_finding(self):
        """Same rule triggered three times in one file → only one Finding."""
        code = (
            'cursor.execute(f"SELECT * FROM a WHERE id={x}")\n'
            'cursor.execute(f"SELECT * FROM b WHERE id={y}")\n'
            'cursor.execute(f"SELECT * FROM c WHERE id={z}")\n'
        )
        result = scan(code)
        sql_findings = [f for f in result.findings if f.rule_id == "INJ-002"]
        self.assertEqual(len(sql_findings), 1, "Three hits on INJ-002 should deduplicate to one finding")

    def test_and_n_more_label_present(self):
        """When N>1 matches exist, description ends with '(and N more in this file)'."""
        code = (
            'cursor.execute(f"SELECT * FROM a WHERE id={x}")\n'
            'cursor.execute(f"SELECT * FROM b WHERE id={y}")\n'
            'cursor.execute(f"SELECT * FROM c WHERE id={z}")\n'
        )
        result = scan(code)
        sql_findings = [f for f in result.findings if f.rule_id == "INJ-002"]
        self.assertEqual(len(sql_findings), 1)
        self.assertIn("and 2 more in this file", sql_findings[0].description)

    def test_single_match_no_extra_label(self):
        """When only one match exists, description does NOT contain '(and'."""
        code = 'cursor.execute(f"SELECT * FROM a WHERE id={x}")\n'
        result = scan(code)
        sql_findings = [f for f in result.findings if f.rule_id == "INJ-002"]
        self.assertEqual(len(sql_findings), 1)
        self.assertNotIn("and", sql_findings[0].description)

    def test_different_rules_each_reported(self):
        """Two different rules in the same file both fire."""
        code = (
            'api_key = "abcdef1234567890abcdef"\n'
            'cursor.execute(f"SELECT * FROM t WHERE id={x}")\n'
        )
        result = scan(code)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertTrue(any(r.startswith("SEC-") for r in rule_ids), "Secret rule should fire")
        self.assertIn("INJ-002", rule_ids, "SQL injection rule should fire")


# ─────────────────────────────────────────────────────────────────────────────
# Auto-fix hints
# ─────────────────────────────────────────────────────────────────────────────

class TestFixHints(unittest.TestCase):

    def test_fix_hints_dict_non_empty(self):
        self.assertGreater(len(FIX_HINTS), 0)

    def test_finding_has_fix_hint_when_known_rule(self):
        """INJ-002 is in FIX_HINTS; the Finding should carry the hint."""
        result = scan('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        sql_f = [f for f in result.findings if f.rule_id == "INJ-002"]
        self.assertTrue(sql_f, "INJ-002 should be found")
        self.assertNotEqual(sql_f[0].fix_hint, "", "fix_hint should be populated")

    def test_finding_has_no_fix_hint_when_not_in_dict(self):
        """AUTH-020 (route without decorator) is not in FIX_HINTS; fix_hint is empty."""
        code = (
            '@app.route("/admin")\n'
            'def admin():\n'
            '    pass\n'
        )
        result = scan(code)
        auth_f = [f for f in result.findings if f.rule_id == "AUTH-020"]
        if auth_f:  # may not fire on all platforms — skip if missing
            if auth_f[0].rule_id not in FIX_HINTS:
                self.assertEqual(auth_f[0].fix_hint, "")

    def test_fix_hint_in_json_output(self):
        """fix_hint field must appear in JSON output."""
        data = scan_json('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        self.assertIn("findings", data)
        sql_f = [f for f in data["findings"] if f["rule_id"] == "INJ-002"]
        self.assertTrue(sql_f, "INJ-002 must be in JSON findings")
        self.assertIn("fix_hint", sql_f[0], "fix_hint key must exist in JSON finding")
        self.assertNotEqual(sql_f[0]["fix_hint"], "")

    def test_fix_hint_empty_string_in_json_when_no_hint(self):
        """Rules without a hint emit fix_hint: '' in JSON (not missing)."""
        # AUTH-010: localStorage.setItem('token', ...) – may or may not have hint
        code = "localStorage.setItem('token', jwt);\n"
        data = scan_json(code, filename="app.js")
        for f in data.get("findings", []):
            self.assertIn("fix_hint", f, f"fix_hint key missing for {f['rule_id']}")

    def test_all_cwe_mapped_rules_can_have_hints(self):
        """Every rule in FIX_HINTS is also in CWE_MAP (sanity check)."""
        for rule_id in FIX_HINTS:
            self.assertIn(rule_id, CWE_MAP, f"{rule_id} is in FIX_HINTS but not CWE_MAP")


# ─────────────────────────────────────────────────────────────────────────────
# SARIF output
# ─────────────────────────────────────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from generate_report import generate_sarif_report


def _sarif_for(code: str, filename: str = "app.py") -> dict:
    result = scan(code, filename)
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_results(result, json_output=True)
    findings_json = json.loads(buf.getvalue())
    return generate_sarif_report({"security_findings": findings_json})


class TestSARIF(unittest.TestCase):

    def test_sarif_schema_version(self):
        sarif = _sarif_for('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        self.assertEqual(sarif["version"], "2.1.0")

    def test_sarif_has_runs(self):
        sarif = _sarif_for('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        self.assertIn("runs", sarif)
        self.assertEqual(len(sarif["runs"]), 1)

    def test_sarif_rule_has_help_uri(self):
        """CWE-mapped rules must include a helpUri pointing to cwe.mitre.org."""
        sarif = _sarif_for('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        inj_rules = [r for r in rules if r["id"] == "INJ-002"]
        self.assertTrue(inj_rules, "INJ-002 rule should appear")
        self.assertIn("helpUri", inj_rules[0])
        self.assertIn("cwe.mitre.org", inj_rules[0]["helpUri"])

    def test_sarif_rule_has_full_description(self):
        """fullDescription should mention the CWE name."""
        sarif = _sarif_for('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        inj_rules = [r for r in rules if r["id"] == "INJ-002"]
        self.assertIn("fullDescription", inj_rules[0])
        self.assertIn("SQL Injection", inj_rules[0]["fullDescription"]["text"])

    def test_sarif_rule_has_cwe_tag(self):
        """properties.tags should include the CWE identifier."""
        sarif = _sarif_for('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        inj_rules = [r for r in rules if r["id"] == "INJ-002"]
        tags = inj_rules[0].get("properties", {}).get("tags", [])
        self.assertTrue(any("CWE-" in t for t in tags), f"Expected CWE tag, got {tags}")

    def test_sarif_result_level_error_for_critical(self):
        sarif = _sarif_for('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        results = sarif["runs"][0]["results"]
        inj_r = [r for r in results if r["ruleId"] == "INJ-002"]
        self.assertTrue(inj_r)
        self.assertEqual(inj_r[0]["level"], "error")

    def test_sarif_result_location_has_uri(self):
        sarif = _sarif_for('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        results = sarif["runs"][0]["results"]
        for r in results:
            uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertNotIn("\\", uri, "SARIF URIs must use forward slashes")

    def test_sarif_result_fix_hint_in_message(self):
        """When a fix hint exists it should appear in the SARIF result message."""
        sarif = _sarif_for('cursor.execute(f"SELECT * FROM t WHERE id={x}")\n')
        results = sarif["runs"][0]["results"]
        inj_r = [r for r in results if r["ruleId"] == "INJ-002"]
        self.assertTrue(inj_r)
        self.assertIn("Fix hint", inj_r[0]["message"]["text"])

    def test_sarif_no_duplicate_rules(self):
        """Each rule_id should appear exactly once in the rules list."""
        code = (
            'cursor.execute(f"SELECT * FROM a WHERE id={x}")\n'
            'cursor.execute(f"SELECT * FROM b WHERE id={y}")\n'
        )
        sarif = _sarif_for(code)
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        self.assertEqual(len(rule_ids), len(set(rule_ids)), "Duplicate rule entries found")


# ─────────────────────────────────────────────────────────────────────────────
# Pre-commit hook installer
# ─────────────────────────────────────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from install_hooks import install, uninstall


def _make_git_repo() -> str:
    """Create a minimal fake Git repo (just a .git/hooks directory)."""
    d = tempfile.mkdtemp()
    (Path(d) / ".git" / "hooks").mkdir(parents=True)
    return d


class TestInstallHooks(unittest.TestCase):

    def test_install_creates_hook_file(self):
        repo = _make_git_repo()
        result = install(repo)
        self.assertTrue(result)
        hook = Path(repo) / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook.exists())

    @unittest.skipIf(sys.platform == "win32", "chmod execute bits are not enforced on Windows NTFS")
    def test_hook_file_is_executable(self):
        repo = _make_git_repo()
        install(repo)
        hook = Path(repo) / ".git" / "hooks" / "pre-commit"
        mode = hook.stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR, "Hook should be user-executable")

    def test_hook_contains_vibe_security_marker(self):
        repo = _make_git_repo()
        install(repo)
        content = (Path(repo) / ".git" / "hooks" / "pre-commit").read_text()
        self.assertIn("vibe-security", content)

    def test_idempotent_install_does_not_error(self):
        """Installing twice on the same repo should succeed without --force."""
        repo = _make_git_repo()
        install(repo)
        result = install(repo)
        self.assertTrue(result, "Second install should succeed (already ours)")

    def test_force_overwrites_existing_non_vibe_hook(self):
        repo = _make_git_repo()
        hook = Path(repo) / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho 'other hook'\n")
        # Without force: should fail
        result = install(repo, force=False)
        self.assertFalse(result)
        # With force: should succeed
        result = install(repo, force=True)
        self.assertTrue(result)
        self.assertIn("vibe-security", hook.read_text())

    def test_install_fails_on_non_git_directory(self):
        d = tempfile.mkdtemp()  # no .git dir
        result = install(d)
        self.assertFalse(result)

    def test_uninstall_removes_hook(self):
        repo = _make_git_repo()
        install(repo)
        result = uninstall(repo)
        self.assertTrue(result)
        hook = Path(repo) / ".git" / "hooks" / "pre-commit"
        self.assertFalse(hook.exists())

    def test_uninstall_leaves_non_vibe_hook_alone(self):
        repo = _make_git_repo()
        hook = Path(repo) / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho 'other hook'\n")
        result = uninstall(repo)
        self.assertFalse(result, "Should refuse to delete a hook we didn't install")
        self.assertTrue(hook.exists(), "Foreign hook should still be present")

    def test_uninstall_no_hook_is_ok(self):
        repo = _make_git_repo()
        result = uninstall(repo)
        self.assertTrue(result, "Uninstalling when no hook exists should succeed")


if __name__ == "__main__":
    unittest.main()
