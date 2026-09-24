"""Development certificates for mTLS without a mesh (Docker Compose, local k3s tests).

Creates a private CA and one certificate per service. Each certificate is valid for both server
and client authentication, so a service presents the same certificate when it calls another one.
Not for production: there, use a mesh (Linkerd) or cert-manager with a real issuer.

    python -m app.cli dev-certs --out /certs --names guardrail-control-plane,guardrail-gateway

Needs the `cryptography` package (installed in the control-plane image).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
from pathlib import Path


def generate(
    out: Path, names: list[str], *, days: int = 30, force: bool = False, owner_uid: int | None = None
) -> list[Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    out.mkdir(parents=True, exist_ok=True)
    ca_crt, ca_key_path = out / "ca.crt", out / "ca.key"
    if ca_crt.exists() and not force and all((out / f"{n}.crt").exists() for n in names):
        return []

    def name(cn: str) -> x509.Name:
        return x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "guardrail-dev"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )

    def pem_key(k: ec.EllipticCurvePrivateKey) -> bytes:
        return k.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    now = dt.datetime.now(dt.UTC)
    if ca_crt.exists() and ca_key_path.exists() and not force:
        ca_cert = x509.load_pem_x509_certificate(ca_crt.read_bytes())
        loaded = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)
        ca_key = loaded
    else:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name("guardrail-dev-ca"))
            .issuer_name(name("guardrail-dev-ca"))
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        _write(ca_key_path, pem_key(ca_key), private=True, owner_uid=owner_uid)
        _write(ca_crt, ca_cert.public_bytes(serialization.Encoding.PEM), owner_uid=owner_uid)

    written = [ca_crt]
    for n in names:
        key = ec.generate_private_key(ec.SECP256R1())
        sans: list[x509.GeneralName] = [
            x509.DNSName(n),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
        cert = (
            x509.CertificateBuilder()
            .subject_name(name(n))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        _write(out / f"{n}.key", pem_key(key), private=True, owner_uid=owner_uid)
        _write(out / f"{n}.crt", cert.public_bytes(serialization.Encoding.PEM), owner_uid=owner_uid)
        written.append(out / f"{n}.crt")
    return written


def _write(path: Path, data: bytes, *, private: bool = False, owner_uid: int | None = None) -> None:
    path.write_bytes(data)
    os.chmod(path, 0o600 if private else 0o644)
    if owner_uid is not None:  # run as root on a fresh volume, hand the files to the services' user
        os.chown(path, owner_uid, owner_uid)
