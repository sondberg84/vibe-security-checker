"""Entry point for `vibe-security-checker` CLI command when installed via pip."""
import sys
from pathlib import Path

# When run directly (not installed), ensure scripts/ is on sys.path
_here = str(Path(__file__).parent)
if _here not in sys.path:
    sys.path.insert(0, _here)

from scan_security import main  # noqa: E402

if __name__ == "__main__":
    main()
