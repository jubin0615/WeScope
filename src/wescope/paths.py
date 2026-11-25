import os
from pathlib import Path

RULES_DIR = Path(__file__).parent / "rules"


def home() -> Path:
    """~/.wescope. 테스트는 WESCOPE_HOME으로 임시 폴더를 쓴다."""
    return Path(os.environ.get("WESCOPE_HOME") or Path.home() / ".wescope")
