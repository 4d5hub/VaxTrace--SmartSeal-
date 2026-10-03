import sys
from pathlib import Path

_GATEWAY = str(Path(__file__).resolve().parents[2] / "gateway")
if _GATEWAY not in sys.path:
    sys.path.append(_GATEWAY)
