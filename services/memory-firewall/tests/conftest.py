"""The tests load the real Memory Firewall library from vendor/ (a verbatim copy, see vendor/VENDORED.md).

Its `src/` is put on sys.path the same way the image sets PYTHONPATH.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "vendor" / "memory-firewall" / "src"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SRC))
# app.selftest runs in a subprocess and needs the library there too.
os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SRC), os.environ.get("PYTHONPATH")]))
