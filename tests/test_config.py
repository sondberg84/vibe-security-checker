"""
Tests for .vibe-security.json config file support.
"""
import sys
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from scan_security import SecurityScanner, ScanConfig, load_config, CONFIG_FILENAME


def make_project(files: dict) -> str:
    tmpdir = tempfile.mkdtemp()
    for name, content in files.items():
        p = Path(tmpdir) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content))
    return tmpdir


VULN_CODE = 'api_key = "abcdef1234567890abcdef"\n'
SQL_CODE  = 'cursor.execute(f"SELECT * FROM t WHERE id={x}")\n'


def scan(project_path, config=None):
    scanner = SecurityScanner(project_path, config=config)
    return scanner.scan()


class TestLoadConfig(unittest.TestCase):

    def test_no_config_file_returns_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(d)
        self.assertIsNone(cfg.checks)
        self.assertEqual(cfg.severity_threshold, "low")
        self.assertEqual(cfg.exclude_paths, [])
        self.assertEqual(cfg.exclude_rules, set())
        self.assertIsNone(cfg.baseline)
        self.assertEqual(cfg.fail_on, "critical")
        self.assertEqual(cfg.custom_patterns, [])

    def test_valid_config_loaded(self):
        project = make_project({CONFIG_FILENAME: {
            "checks": ["secrets", "injection"],
            "severity_threshold": "high",
            "baseline": ".vibe-security-baseline.json",
            "exclude_paths": ["tests/", "docs/"],
            "exclude_rules": ["AUTH-020", "AUTH-021"],
            "fail_on": "high",
        }})
        cfg = load_config(project)
        self.assertEqual(cfg.checks, ["secrets", "injection"])
        self.assertEqual(cfg.severity_threshold, "high")
        self.assertEqual(cfg.baseline, ".vibe-security-baseline.json")
        self.assertIn("tests/", cfg.exclude_paths)
        self.assertIn("AUTH-020", cfg.exclude_rules)
        self.assertEqual(cfg.fail_on, "high")

    def test_malformed_config_returns_defaults(self):
        project = make_project({CONFIG_FILENAME: "this is not json {"})
        cfg = load_config(project)
        self.assertIsNone(cfg.checks)  # defaults


class TestExcludePaths(unittest.TestCase):

    def test_excluded_path_not_scanned(self):
        project = make_project({
            "src/app.py": VULN_CODE,
            "tests/fixtures/app.py": VULN_CODE,
            CONFIG_FILENAME: {"exclude_paths": ["tests/"]},
        })
        cfg = load_config(project)
        result = scan(project, config=cfg)
        # Only src/app.py should be scanned, not tests/fixtures/app.py
        scanned_files = {f.file_path for f in result.findings}
        self.assertTrue(all("tests" not in f for f in scanned_files),
            "Files under excluded path should not generate findings")

    def test_non_excluded_path_still_scanned(self):
        project = make_project({
            "src/app.py": VULN_CODE,
            CONFIG_FILENAME: {"exclude_paths": ["tests/"]},
        })
        cfg = load_config(project)
        result = scan(project, config=cfg)
        self.assertGreater(len(result.findings), 0)


class TestExcludeRules(unittest.TestCase):

    def test_excluded_rule_suppressed(self):
        project = make_project({"app.py": VULN_CODE})
        config = ScanConfig(exclude_rules={"SEC-013", "SEC-017", "SEC-018",
                                            "SEC-019", "SEC-020", "SEC-021"})
        result = scan(project, config=config)
        rule_ids = {f.rule_id for f in result.findings}
        for suppressed in ("SEC-013", "SEC-017", "SEC-018"):
            self.assertNotIn(suppressed, rule_ids)

    def test_non_excluded_rule_not_suppressed(self):
        project = make_project({"app.py": VULN_CODE})
        config = ScanConfig(exclude_rules={"INJ-002"})  # exclude SQL, not secrets
        result = scan(project, config=config)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertTrue(
            any(r.startswith("SEC-") for r in rule_ids),
            "Secret rules should still fire"
        )


class TestCustomPatterns(unittest.TestCase):

    def test_custom_pattern_detected(self):
        project = make_project({
            "app.py": 'token = "internal_tok_abc123def456ghi789"\n',
            CONFIG_FILENAME: {
                "custom_patterns": [{
                    "rule_id": "CUSTOM-001",
                    "pattern": "internal_tok_[a-z0-9]{18}",
                    "severity": "CRITICAL",
                    "description": "Internal token exposed",
                    "remediation": "Rotate token",
                }]
            },
        })
        cfg = load_config(project)
        result = scan(project, config=cfg)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("CUSTOM-001", rule_ids)

    def test_no_custom_patterns_no_custom_findings(self):
        project = make_project({"app.py": VULN_CODE})
        config = ScanConfig()
        result = scan(project, config=config)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("CUSTOM-001", rule_ids)


class TestChecksSubset(unittest.TestCase):

    def test_only_configured_checks_run(self):
        project = make_project({"app.py": VULN_CODE + SQL_CODE})
        config = ScanConfig(checks=["secrets"])
        result = scan(project, config=config)
        rule_ids = {f.rule_id for f in result.findings}
        # SQL injection rules should not appear
        self.assertFalse(any(r.startswith("INJ-00") for r in rule_ids),
            "SQL injection should not run when checks=['secrets']")
        # Secrets should appear
        self.assertTrue(any(r.startswith("SEC-") for r in rule_ids))


if __name__ == "__main__":
    unittest.main()
