"""mTLS between services without a mesh: certificates, the internal listener and the route guard."""

import asyncio
import datetime as dt
import ipaddress
import socket

import httpx
import pytest

from guardrail_sdk.serving import InternalRouteGuard, Listeners, serve
from guardrail_sdk.tls import ClientTLS, ServerTLS, TLSConfigError

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

pytest.importorskip("uvicorn")


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(ca_key, ca_cert, cn, *, server):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )
    if server:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
    return key, b.sign(ca_key, hashes.SHA256())


def _write(path, key, cert):
    path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        path.with_suffix(".key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    return str(path.with_suffix(".crt")), str(path.with_suffix(".key"))


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca_key, ca = _ca("guardrail-ca")
    rogue_key, rogue_ca = _ca("rogue-ca")
    ca_crt, _ = _write(d / "ca", None, ca)
    srv = _write(d / "server", *_leaf(ca_key, ca, "control-plane", server=True))
    cli = _write(d / "client", *_leaf(ca_key, ca, "gateway", server=False))
    bad = _write(d / "rogue", *_leaf(rogue_key, rogue_ca, "attacker", server=False))
    return {"ca": ca_crt, "server": srv, "client": cli, "rogue": bad}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    body = f'{{"path": "{scope["path"]}", "port": {scope["server"][1]}}}'.encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


def test_config_validation(pki, tmp_path):
    cert, key = pki["server"]
    assert not ServerTLS.from_env({}).enabled and ClientTLS.from_env({}).ssl_context() is True
    with pytest.raises(TLSConfigError):
        ServerTLS.from_env({"TLS_CERT_FILE": cert})  # key missing
    with pytest.raises(TLSConfigError):
        ServerTLS.from_env({"TLS_CLIENT_CA_FILE": pki["ca"]})  # mTLS without a server cert
    with pytest.raises(TLSConfigError):
        ClientTLS.from_env({"TLS_CA_FILE": str(tmp_path / "missing.pem")})
    with pytest.raises(ValueError):  # the public port can't require client certificates
        Listeners.from_env(8200, {"TLS_CERT_FILE": cert, "TLS_KEY_FILE": key, "TLS_CLIENT_CA_FILE": pki["ca"]})
    with pytest.raises(ValueError):
        Listeners.from_env(8200, {"INTERNAL_PORT": "8200"})
    ok = Listeners.from_env(
        8200, {"INTERNAL_PORT": "8201", "TLS_CERT_FILE": cert, "TLS_KEY_FILE": key, "TLS_CLIENT_CA_FILE": pki["ca"]}
    )
    assert ok.tls.mutual and ok.internal_port == 8201 and ok.port == 8200
    kw = ok.tls.uvicorn_kwargs(require_client_cert=True)
    assert kw["ssl_ca_certs"] == pki["ca"] and kw["ssl_cert_reqs"] == 2


async def test_internal_route_guard_uses_the_listening_port():
    guard = InternalRouteGuard(_app, ["/cp/v1/internal"], internal_port=8201)
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request"}

    for port, path, expect in (
        (8200, "/cp/v1/internal/catalog", 404),
        (8200, "/cp/v1/internalx", 200),  # prefix must match a whole segment
        (8201, "/cp/v1/internal/catalog", 200),
        (8200, "/cp/v1/tenants", 200),
    ):
        sent.clear()
        await guard({"type": "http", "path": path, "server": ("10.0.0.1", port)}, receive, send)
        assert sent[0]["status"] == expect, (port, path)


async def test_mtls_internal_listener_end_to_end(pki):
    cert, key = pki["server"]
    public, internal = _free_port(), _free_port()
    listeners = Listeners.from_env(
        0,
        {
            "HOST": "127.0.0.1",
            "PORT": str(public),
            "INTERNAL_PORT": str(internal),
            "TLS_CERT_FILE": cert,
            "TLS_KEY_FILE": key,
            "TLS_CLIENT_CA_FILE": pki["ca"],
        },
    )
    stop = asyncio.Event()
    task = asyncio.create_task(serve(_app, listeners, ["/internal"], stop=stop))
    try:
        for _ in range(100):  # wait for both listeners
            try:
                socket.create_connection(("127.0.0.1", internal), timeout=0.1).close()
                break
            except OSError:
                await asyncio.sleep(0.05)
        good = ClientTLS(ca_file=pki["ca"], cert_file=pki["client"][0], key_file=pki["client"][1]).ssl_context()
        no_cert = ClientTLS(ca_file=pki["ca"]).ssl_context()
        rogue = ClientTLS(ca_file=pki["ca"], cert_file=pki["rogue"][0], key_file=pki["rogue"][1]).ssl_context()

        async with httpx.AsyncClient() as plain:
            assert (await plain.get(f"http://127.0.0.1:{public}/health")).status_code == 200
            assert (await plain.get(f"http://127.0.0.1:{public}/internal/simulate")).status_code == 404
        async with httpx.AsyncClient(verify=good) as c:
            r = await c.get(f"https://localhost:{internal}/internal/simulate")
            assert r.status_code == 200 and r.json()["port"] == internal
        for ctx in (no_cert, rogue):
            async with httpx.AsyncClient(verify=ctx) as c:
                with pytest.raises(httpx.HTTPError):
                    await c.get(f"https://localhost:{internal}/internal/simulate")
    finally:
        stop.set()
        await asyncio.wait_for(task, 10)


def test_dev_certs_work_for_mtls(tmp_path):
    from guardrail_sdk.devcerts import generate

    written = generate(tmp_path, ["guardrail-control-plane", "guardrail-gateway"])
    assert len(written) == 3 and generate(tmp_path, ["guardrail-control-plane", "guardrail-gateway"]) == []
    srv = ServerTLS.from_env(
        {
            "TLS_CERT_FILE": str(tmp_path / "guardrail-control-plane.crt"),
            "TLS_KEY_FILE": str(tmp_path / "guardrail-control-plane.key"),
            "TLS_CLIENT_CA_FILE": str(tmp_path / "ca.crt"),
        }
    )
    srv.ssl_context(require_client_cert=True)
    cli = ClientTLS.from_env(
        {
            "TLS_CA_FILE": str(tmp_path / "ca.crt"),
            "TLS_CLIENT_CERT_FILE": str(tmp_path / "guardrail-gateway.crt"),
            "TLS_CLIENT_KEY_FILE": str(tmp_path / "guardrail-gateway.key"),
        }
    )
    cli.ssl_context()
    cert = x509.load_pem_x509_certificate((tmp_path / "guardrail-gateway.crt").read_bytes())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "guardrail-gateway" in sans.get_values_for_type(x509.DNSName)
    assert oct((tmp_path / "guardrail-gateway.key").stat().st_mode)[-3:] == "600"
    # adding a service later reuses the CA
    ca_before = (tmp_path / "ca.crt").read_bytes()
    generate(tmp_path, ["guardrail-control-plane", "guardrail-gateway", "opa"])
    assert (tmp_path / "ca.crt").read_bytes() == ca_before and (tmp_path / "opa.crt").exists()
