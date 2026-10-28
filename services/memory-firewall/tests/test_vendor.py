"""The vendored library is byte-for-byte what vendor/SHA256SUMS records (see vendor/VENDORED.md)."""

import hashlib
from pathlib import Path

VENDOR = Path(__file__).resolve().parents[1] / "vendor"
LIB = VENDOR / "memory-firewall"


def recorded() -> dict[str, str]:
    out = {}
    for line in (VENDOR / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split(maxsplit=1)
        out[name.lstrip("*")] = digest
    return out


def test_vendored_library_is_unmodified():
    expected = recorded()
    actual = {
        p.relative_to(LIB).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in LIB.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    assert actual.keys() == expected.keys(), "files were added to or removed from the vendored library"
    changed = sorted(name for name, digest in actual.items() if digest != expected[name])
    assert changed == [], f"vendored files differ from SHA256SUMS (edit the source repository instead): {changed}"
