"""Ed25519 signing keys for Guard, with key-rotation support.

Keys live in a directory kept OUTSIDE the checkpoint database (brief §5: the attacker may
write to the DB but cannot read the key). Layout:

    <key_dir>/ed25519_current.key   current PRIVATE key (32 raw bytes, chmod-restricted)
    <key_dir>/<id>.pub              one PUBLIC key per generation (32 raw bytes)

The Verifier trusts every ``*.pub`` in the directory, so after rotation old entries signed
with a retired key still verify (brief §12 #2: rotating keys must not cause false rejects).
Signing always uses the current private key.
"""

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PRIV_NAME = "ed25519_current.key"


def _pub_id(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()[:16]


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._priv = private_key

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    def public_raw(self) -> bytes:
        return self._priv.public_key().public_bytes_raw()


class Verifier:
    """Verifies a signature against any trusted public key in the directory."""

    def __init__(self, public_keys: list[bytes]) -> None:
        self._pubs = [Ed25519PublicKey.from_public_bytes(p) for p in public_keys]

    def verify(self, data: bytes, signature: bytes) -> bool:
        for pub in self._pubs:
            try:
                pub.verify(signature, data)
                return True
            except Exception:
                continue
        return False


def load_or_create_signer(key_dir: Path) -> Signer:
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / PRIV_NAME
    if priv_path.exists():
        priv = Ed25519PrivateKey.from_private_bytes(priv_path.read_bytes())
    else:
        priv = Ed25519PrivateKey.generate()
        priv_path.write_bytes(priv.private_bytes_raw())
        _write_pub(key_dir, priv.public_key())
    # Make sure a matching .pub exists (e.g. if only the private key was restored).
    _write_pub(key_dir, priv.public_key())
    return Signer(priv)


def rotate_key(key_dir: Path) -> Signer:
    """Generate a NEW current private key, keeping every old public key trusted."""
    key_dir.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    (key_dir / PRIV_NAME).write_bytes(priv.private_bytes_raw())
    _write_pub(key_dir, priv.public_key())
    return Signer(priv)


def load_verifier(key_dir: Path) -> Verifier:
    pubs = [p.read_bytes() for p in sorted(key_dir.glob("*.pub"))]
    if not pubs:
        raise FileNotFoundError(f"No public keys (*.pub) in {key_dir}")
    return Verifier(pubs)


def _write_pub(key_dir: Path, pub: Ed25519PublicKey) -> None:
    raw = pub.public_bytes_raw()
    path = key_dir / f"{_pub_id(raw)}.pub"
    if not path.exists():
        path.write_bytes(raw)
