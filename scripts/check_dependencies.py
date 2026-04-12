#!/usr/bin/env python3
"""
Vibe Security Checker - Dependency Analysis
Detects supply chain risks including hallucinated packages and known CVEs via OSV.dev
"""

import os
import json
import argparse
import sys
import subprocess
import re
import urllib.request
import urllib.error
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 15  # seconds

# Ecosystem names as OSV expects them
ECOSYSTEM_PYPI = "PyPI"
ECOSYSTEM_NPM  = "npm"

# Known typosquats — {typo_name: legitimate_name_or_None}
# None means the package itself IS the problem (abandoned/malicious)
KNOWN_TYPOSQUATS: Dict[str, Dict[str, Optional[str]]] = {
    "python": {
        # Malicious / abandoned packages
        "crypto":           "pycryptodome",      # 'crypto' on PyPI is a malicious squatter
        "pycrypto":         "pycryptodome",      # pycrypto is abandoned, has CVEs
        "python-jwt":       "PyJWT",             # python-jwt had critical auth bypass (CVE-2022-39227)
        # Common typos of popular packages
        "colourama":        "colorama",
        "coloarama":        "colorama",
        "requets":          "requests",
        "reqeusts":         "requests",
        "requsets":         "requests",
        "urllib2":          "urllib (built-in, Python 3)",
        "python-dateutils": "python-dateutil",
        "pyymal":           "pyyaml",
        "beautifulsoup":    "beautifulsoup4",
        "sklearn":          "scikit-learn",      # sklearn alone installs a warning pkg
        "cv2":              "opencv-python",
        "mysql-python":     "mysqlclient",       # mysql-python is abandoned
        "Pillow-PIL":       "Pillow",
        "tensorflow-gpu":   None,                # deprecated, use tensorflow>=2.12
        "openai-whisper":   "openai-whisper",    # real but often confused with 'openai'
    },
    "npm": {
        # Confirmed malicious / abandoned
        "crossenv":         "cross-env",         # malicious package (2018 supply chain attack)
        "cross.env":        "cross-env",
        "node-openssl":     "node-forge",        # known malicious squatter
        # Common typos
        "lodahs":           "lodash",
        "lodasch":          "lodash",
        "expres":           "express",
        "expresss":         "express",
        "reacts":           "react",
        "axois":            "axios",
        "momet":            "moment",
        "momnet":           "moment",
        "mongose":          "mongoose",
        "mongooes":         "mongoose",
        "typscript":        "typescript",
        "nodmon":           "nodemon",
        "jquer":            "jquery",
        "jqurey":           "jquery",
        "discordjs":        "discord.js",
        "sequlize":         "sequelize",
    },
}

# Known hallucinated packages that AI frequently generates
HALLUCINATED_PACKAGES = {
    'python': {
        'huggingface-cli',       # Real package is 'huggingface-hub'
        'flask-security-utils',
        'django-rest-utils',
        'pytorch-utils',
        'tensorflow-utils',
        'numpy-tools',
        'pandas-utils',
        'scikit-utils',
        'aws-sdk',               # Real package is 'boto3'
        'google-cloud-utils',
        'openai-utils',
        'langchain-utils',
    },
    'npm': {
        'react-utils',
        'vue-utils',
        'next-utils',
        'express-utils',
        'node-utils',
        'typescript-utils',
        'mongodb-utils',
        'postgres-utils',
        'aws-sdk-utils',
        'stripe-utils',
    }
}


@dataclass
class DependencyFinding:
    package: str
    version: Optional[str]
    issue_type: str  # 'hallucinated', 'vulnerable', 'suspicious'
    severity: str
    description: str
    file_path: str
    remediation: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _osv_severity(vuln: dict) -> tuple:
    """Return (severity_label, cvss_score) from an OSV vulnerability object."""
    # Try database_specific first (pre-computed)
    db = vuln.get("database_specific", {})
    label = db.get("severity", "").upper()

    # Try ecosystem_specific (npm)
    for affected in vuln.get("affected", []):
        eco = affected.get("ecosystem_specific", {})
        if eco.get("severity"):
            label = eco["severity"].upper()
            break

    # Map non-standard labels
    label_map = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "NEGLIGIBLE": "LOW"}
    label = label_map.get(label, label)
    if label not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        label = "HIGH"  # safe default if unknown

    return label, None


def query_osv_batch(packages: List[Dict]) -> List[List[dict]]:
    """
    Query OSV.dev for multiple packages at once.
    packages: list of {"name": str, "ecosystem": str, "version": str|None}
    Returns: list of vuln lists, one per input package (empty list = no vulns).
    """
    queries = []
    for pkg in packages:
        q = {"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]}}
        if pkg.get("version"):
            q["version"] = pkg["version"]
        queries.append(q)

    payload = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            data = json.loads(resp.read())
            return [r.get("vulns", []) for r in data.get("results", [])]
    except (urllib.error.URLError, OSError):
        return [[] for _ in packages]


class DependencyChecker:
    def __init__(self, root_path: str):
        self.root = Path(root_path).resolve()
        self.findings: List[DependencyFinding] = []
        self._osv_available = True

    def check(self) -> List[DependencyFinding]:
        """Run all dependency checks."""
        self._check_requirements_files()
        self._check_package_json()
        self._check_python_deps()
        self._check_npm_deps()
        return self.findings

    # ------------------------------------------------------------------
    # File parsing
    # ------------------------------------------------------------------

    def _check_requirements_files(self):
        req_files = list(self.root.glob("**/requirements*.txt"))
        req_files.extend(self.root.glob("**/pyproject.toml"))

        for req_file in req_files:
            if "node_modules" in str(req_file) or ".venv" in str(req_file):
                continue
            try:
                content = req_file.read_text(encoding="utf-8", errors="ignore")
                if req_file.suffix == ".txt":
                    packages = self._parse_requirements_txt(content)
                else:
                    packages = self._parse_pyproject(content)

                rel = str(req_file.relative_to(self.root))
                self._check_python_packages(packages, rel)
            except Exception:
                pass

    def _parse_requirements_txt(self, content: str) -> Dict[str, Optional[str]]:
        packages = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([a-zA-Z0-9_-]+)(?:\[.*\])?(?:([=<>!~]+)(.+))?", line)
            if match:
                pkg = match.group(1).lower()
                version = match.group(3).strip() if match.group(3) else None
                packages[pkg] = version
        return packages

    def _parse_pyproject(self, content: str) -> Dict[str, Optional[str]]:
        packages = {}
        deps_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if deps_match:
            for match in re.finditer(
                r'["\']([a-zA-Z0-9_-]+)(?:[=<>!~]+([^"\']+))?["\']',
                deps_match.group(1),
            ):
                packages[match.group(1).lower()] = match.group(2)
        return packages

    def _check_package_json(self):
        for pkg_file in self.root.glob("**/package.json"):
            if "node_modules" in str(pkg_file):
                continue
            try:
                content = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
                rel = str(pkg_file.relative_to(self.root))
                npm_pkgs = {}
                for dep_type in ("dependencies", "devDependencies"):
                    if dep_type in content:
                        for pkg, ver in content[dep_type].items():
                            npm_pkgs[pkg.lower()] = (pkg, ver)
                self._check_npm_packages(npm_pkgs, rel)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Hallucination checks (static, no network)
    # ------------------------------------------------------------------

    def _flag_typosquat(self, pkg: str, legitimate: Optional[str], file_path: str):
        if legitimate:
            desc = f'"{pkg}" looks like a typosquat of "{legitimate}" — possible supply chain attack'
            fix = f'Did you mean "{legitimate}"? Verify the package name before installing.'
        else:
            desc = f'"{pkg}" is a known malicious or abandoned package'
            fix = f'Remove "{pkg}" immediately and check for alternatives.'
        self.findings.append(DependencyFinding(
            package=pkg,
            version=None,
            issue_type="typosquat",
            severity="CRITICAL",
            description=desc,
            file_path=file_path,
            remediation=fix,
        ))

    def _flag_hallucinated(self, pkg: str, file_path: str, ecosystem: str):
        tip = "pypi.org" if ecosystem == "python" else "npmjs.com"
        self.findings.append(DependencyFinding(
            package=pkg,
            version=None,
            issue_type="hallucinated",
            severity="CRITICAL",
            description=f'"{pkg}" is commonly hallucinated by AI and may not exist',
            file_path=file_path,
            remediation=f"Verify the package exists on {tip} before installing",
        ))

    def _flag_unpinned(self, pkg: str, version: str, file_path: str, fix_cmd: str):
        self.findings.append(DependencyFinding(
            package=pkg,
            version=version,
            issue_type="suspicious",
            severity="MEDIUM",
            description=f'"{pkg}" uses unpinned version "{version}" — supply chain risk',
            file_path=file_path,
            remediation=fix_cmd,
        ))

    # ------------------------------------------------------------------
    # OSV vulnerability checks
    # ------------------------------------------------------------------

    def _check_python_packages(self, packages: Dict[str, Optional[str]], file_path: str):
        """Hallucination check (static) + typosquat check + OSV batch query for vulnerabilities."""
        for pkg, version in packages.items():
            if pkg in HALLUCINATED_PACKAGES["python"]:
                self._flag_hallucinated(pkg, file_path, "python")
            elif pkg in KNOWN_TYPOSQUATS["python"]:
                self._flag_typosquat(pkg, KNOWN_TYPOSQUATS["python"][pkg], file_path)

        if self._osv_available:
            self._osv_check(
                [{"name": pkg, "ecosystem": ECOSYSTEM_PYPI, "version": ver}
                 for pkg, ver in packages.items()],
                list(packages.keys()),
                file_path,
                upgrade_cmd="pip install --upgrade {pkg}",
            )

    def _check_npm_packages(self, packages: Dict[str, tuple], file_path: str):
        """packages: {lower_name: (original_name, version)}"""
        for lower, (orig, version) in packages.items():
            if lower in HALLUCINATED_PACKAGES["npm"]:
                self._flag_hallucinated(orig, file_path, "npm")
            elif lower in KNOWN_TYPOSQUATS["npm"]:
                self._flag_typosquat(orig, KNOWN_TYPOSQUATS["npm"][lower], file_path)
            if version in ("*", "latest", ""):
                self._flag_unpinned(orig, version, file_path,
                                    f"npm install {orig}@<version> --save-exact")

        if self._osv_available:
            self._osv_check(
                [{"name": orig, "ecosystem": ECOSYSTEM_NPM, "version": ver}
                 for _, (orig, ver) in packages.items()],
                [orig for _, (orig, _) in packages.items()],
                file_path,
                upgrade_cmd="npm update {pkg}",
            )

    def _osv_check(self, queries: list, names: list, file_path: str, upgrade_cmd: str):
        """Run OSV batch query and create findings for any vulnerabilities found."""
        if not queries:
            return

        try:
            results = query_osv_batch(queries)
        except Exception:
            self._osv_available = False
            return

        if all(r == [] for r in results):
            return

        for pkg_info, vulns in zip(queries, results):
            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN")
                aliases = vuln.get("aliases", [])
                cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                summary = vuln.get("summary", "Security vulnerability")
                severity_label, cvss = _osv_severity(vuln)

                self.findings.append(DependencyFinding(
                    package=pkg_info["name"],
                    version=pkg_info.get("version"),
                    issue_type="vulnerable",
                    severity=severity_label,
                    description=f"{cve}: {summary}",
                    file_path=file_path,
                    remediation=upgrade_cmd.format(pkg=pkg_info["name"]),
                    cve_id=cve,
                    cvss_score=cvss,
                ))

    # ------------------------------------------------------------------
    # Optional: pip-audit / npm audit
    # ------------------------------------------------------------------

    def _check_python_deps(self):
        """Try to run pip-audit if available (deeper installed-env scan)."""
        try:
            result = subprocess.run(
                ["pip-audit", "--desc", "--format", "json"],
                capture_output=True, text=True, cwd=self.root, timeout=60,
            )
            if result.returncode == 0:
                for vuln in json.loads(result.stdout):
                    vuln_id = vuln.get("vulns", [{}])[0].get("id", "Unknown")
                    self.findings.append(DependencyFinding(
                        package=vuln.get("name", "unknown"),
                        version=vuln.get("version"),
                        issue_type="vulnerable",
                        severity="HIGH",
                        description=f"{vuln_id} (via pip-audit)",
                        file_path="(installed environment)",
                        remediation=f"pip install --upgrade {vuln.get('name')}",
                        cve_id=vuln_id,
                    ))
        except Exception:
            pass

    def _check_npm_deps(self):
        """Try to run npm audit if package-lock.json exists."""
        if not (self.root / "package-lock.json").exists():
            return
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True, text=True, cwd=self.root, timeout=60,
            )
            audit_data = json.loads(result.stdout)
            for pkg, info in audit_data.get("vulnerabilities", {}).items():
                via = info.get("via", [{}])
                title = via[0].get("title", "Security vulnerability") if isinstance(via[0], dict) else str(via)
                self.findings.append(DependencyFinding(
                    package=pkg,
                    version=info.get("range"),
                    issue_type="vulnerable",
                    severity=info.get("severity", "HIGH").upper(),
                    description=f"{title} (via npm audit)",
                    file_path="package-lock.json",
                    remediation=f"npm audit fix or npm update {pkg}",
                ))
        except Exception:
            pass


# ------------------------------------------------------------------
# Output
# ------------------------------------------------------------------

def print_results(findings: List[DependencyFinding], json_output: bool = False):
    if json_output:
        print(json.dumps({
            "total_findings": len(findings),
            "findings": [
                {
                    "package": f.package,
                    "version": f.version,
                    "type": f.issue_type,
                    "severity": f.severity,
                    "description": f.description,
                    "file": f.file_path,
                    "remediation": f.remediation,
                    "cve_id": f.cve_id,
                    "cvss_score": f.cvss_score,
                }
                for f in findings
            ],
        }, indent=2))
        return

    print(f"\n{'='*60}")
    print("VIBE SECURITY CHECKER - DEPENDENCY ANALYSIS")
    print(f"{'='*60}\n")
    print(f"Total findings: {len(findings)}\n")

    hallucinated = [f for f in findings if f.issue_type == "hallucinated"]
    typosquats   = [f for f in findings if f.issue_type == "typosquat"]
    vulnerable   = [f for f in findings if f.issue_type == "vulnerable"]
    suspicious   = [f for f in findings if f.issue_type == "suspicious"]

    if typosquats:
        print("CRITICAL - SUSPECTED TYPOSQUATS / MALICIOUS PACKAGES:")
        print("-" * 50)
        for f in typosquats:
            print(f"  {f.package}")
            print(f"    File:   {f.file_path}")
            print(f"    Issue:  {f.description}")
            print(f"    Action: {f.remediation}")
        print()

    if hallucinated:
        print("CRITICAL - POTENTIALLY HALLUCINATED PACKAGES:")
        print("-" * 50)
        for f in hallucinated:
            print(f"  {f.package}")
            print(f"    File:   {f.file_path}")
            print(f"    Action: {f.remediation}")
        print()

    if vulnerable:
        print("VULNERABLE PACKAGES (via OSV.dev):")
        print("-" * 50)
        for f in vulnerable:
            score_str = f" (CVSS {f.cvss_score})" if f.cvss_score else ""
            print(f"  [{f.severity}]{score_str} {f.package} {f.version or ''}")
            print(f"    {f.description}")
            print(f"    Fix: {f.remediation}")
        print()

    if suspicious:
        print("SUSPICIOUS CONFIGURATIONS:")
        print("-" * 50)
        for f in suspicious:
            print(f"  {f.package}: {f.description}")
            print(f"    Fix: {f.remediation}")
        print()

    if not findings:
        print("No dependency issues found.")
    else:
        if typosquats:
            print(f"{len(typosquats)} suspected typosquat(s) — remove immediately.")
        if hallucinated:
            print(f"{len(hallucinated)} package(s) may be hallucinated — verify before installing.")


def main():
    parser = argparse.ArgumentParser(description="Check dependencies for supply chain risks")
    parser.add_argument("path", help="Path to project directory")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit with code 1 if findings")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)

    checker = DependencyChecker(args.path)
    findings = checker.check()
    print_results(findings, args.json)

    if args.fail_on_findings and findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
