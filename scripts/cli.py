"""Entry point for `vibe-security-checker` CLI command when installed via pip."""
import sys
from pathlib import Path

# Ensure the scripts directory is on sys.path so bare imports (from _models import ...)
# work whether the tool is run directly or installed via pip.
_scripts_dir = str(Path(__file__).parent)
if _scripts_dir not in sys.path:
    sys.path.insert(0, _scripts_dir)

from scan_security import main  # noqa: E402

if __name__ == "__main__":
    main()
