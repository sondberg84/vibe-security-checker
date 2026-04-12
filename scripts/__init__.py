"""
vibe-security-checker — security scanner for AI-generated code.

Public API:
    from vibe_security_checker import SecurityScanner, ScanConfig, Finding, Severity
"""
try:
    from .scan_security import SecurityScanner, __version__
    from ._models import Finding, ScanResult, Severity
    from ._config import ScanConfig, load_config
    from ._baseline import save_baseline, load_baseline, apply_baseline
except ImportError:
    pass  # running as scripts, not installed as package
