"""Synthetic certificate tests; no real trust-store changes, network or CA keys."""

import ipaddress
import os
import subprocess
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scripts import greenfield_https as tls


def certificate(key, issuer_key, subject, issuer, hosts=(), expiry=30):
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=expiry))
        .add_extension(x509.BasicConstraints(ca=not hosts, path_length=None), critical=True)
    )
    if hosts:
        names = [
            x509.DNSName(name) if name == "localhost" else x509.IPAddress(ipaddress.ip_address(name)) for name in hosts
        ]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def pair(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic CA")])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    root, cert, key = [tmp_path / name for name in ("rootCA.pem", "cert.pem", "cert-key.pem")]
    root.write_bytes(certificate(root_key, root_key, issuer, issuer))
    cert.write_bytes(certificate(leaf_key, root_key, subject, issuer, tls.HOSTS))
    key.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    key.chmod(0o600)
    monkeypatch.setattr(tls, "local_ca", lambda: ("synthetic-mkcert", root))
    monkeypatch.setattr(tls, "system_trusted", lambda *a, **k: True)
    return tmp_path, cert, key, root, leaf_key, root_key, subject, issuer


def test_valid_pair_reused_without_generation_or_replacement(pair, monkeypatch):
    state, cert, key, root, *_ = pair
    before = (cert.read_bytes(), key.stat().st_ino)
    command = Mock(side_effect=AssertionError("unnecessary generation"))
    monkeypatch.setattr(tls.subprocess, "run", command)
    _, _, _, metadata = tls.ensure_certificate(state, prepare=True)
    assert metadata["macos_trusted"] is True
    assert set(metadata["sans"]) == set(tls.HOSTS)
    assert before == (cert.read_bytes(), key.stat().st_ino)
    command.assert_not_called()


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666, 0o400])
def test_unsafe_leaf_key_modes_refused(pair, mode):
    state, _, key, *_ = pair
    key.chmod(mode)
    with pytest.raises(tls.HttpsTrustError, match="0600"):
        tls.ensure_certificate(state, prepare=True)


def test_symlink_private_key_refused(pair):
    state, _, key, *_ = pair
    key.rename(state / "original-key")
    key.symlink_to(state / "original-key")
    with pytest.raises(OSError):
        tls.ensure_certificate(state, prepare=True)


def test_hardlink_private_key_refused(pair):
    state, _, key, *_ = pair
    os.link(key, state / "duplicate-key")
    with pytest.raises(tls.HttpsTrustError, match="single-link"):
        tls.ensure_certificate(state)


def test_public_or_symlink_directory_refused(pair):
    state, *_ = pair
    state.chmod(0o755)
    with pytest.raises(tls.HttpsTrustError, match="0700"):
        tls.ensure_certificate(state)


def test_key_mismatch_refused(pair):
    _, cert, key, root, _, root_key, *_ = pair
    key.write_bytes(
        root_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    with pytest.raises(tls.HttpsTrustError, match="match its key"):
        tls.validate_pair(cert, key, root)


@pytest.mark.parametrize("hosts", [("localhost", "127.0.0.1"), ("127.0.0.1", "::1")])
def test_missing_san_refused(pair, hosts):
    _, cert, key, root, leaf_key, root_key, subject, issuer = pair
    cert.write_bytes(certificate(leaf_key, root_key, subject, issuer, hosts))
    with pytest.raises(tls.HttpsTrustError, match="covering exactly"):
        tls.validate_pair(cert, key, root)


def test_unexpected_extra_san_refused(pair):
    _, cert, key, root, leaf_key, root_key, subject, issuer = pair
    cert.write_bytes(certificate(leaf_key, root_key, subject, issuer, (*tls.HOSTS, "192.0.2.1")))
    with pytest.raises(tls.HttpsTrustError):
        tls.validate_pair(cert, key, root)


def test_near_expiry_refused(pair):
    _, cert, key, root, leaf_key, root_key, subject, issuer = pair
    cert.write_bytes(certificate(leaf_key, root_key, subject, issuer, tls.HOSTS, expiry=2))
    with pytest.raises(tls.HttpsTrustError, match="seven days"):
        tls.validate_pair(cert, key, root)


def test_different_ca_refused(pair):
    _, cert, key, root, leaf_key, _, subject, issuer = pair
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert.write_bytes(certificate(leaf_key, other, subject, issuer, tls.HOSTS))
    with pytest.raises(tls.HttpsTrustError):
        tls.validate_pair(cert, key, root)


def test_untrusted_leaf_blocks_readiness(pair, monkeypatch):
    state, *_ = pair
    monkeypatch.setattr(tls, "system_trusted", lambda *a, **k: False)
    with pytest.raises(tls.HttpsTrustError, match="trust check failed"):
        tls.ensure_certificate(state)


def test_missing_pair_check_never_generates(pair, monkeypatch):
    state, cert, *_ = pair
    cert.unlink()
    command = Mock()
    monkeypatch.setattr(tls.subprocess, "run", command)
    with pytest.raises(tls.HttpsTrustError, match="trust check failed"):
        tls.ensure_certificate(state)
    command.assert_not_called()


def test_untrusted_ca_stops_before_generation(pair, monkeypatch):
    state, *_ = pair
    monkeypatch.setattr(tls, "local_ca", Mock(side_effect=tls.HttpsTrustError("operator approval required")))
    command = Mock()
    monkeypatch.setattr(tls.subprocess, "run", command)
    with pytest.raises(tls.HttpsTrustError, match="operator approval"):
        tls.ensure_certificate(state, prepare=True)
    command.assert_not_called()


def test_generation_only_leaf_retains_old_pair(pair, monkeypatch):
    state, cert, key, _, leaf_key, root_key, subject, issuer = pair
    old_cert = b"obsolete certificate"
    cert.write_bytes(old_cert)

    def generate(args, **kwargs):
        assert "-install" not in args
        assert args[-3:] == list(tls.HOSTS)
        assert "CAROOT" not in kwargs["env"]
        destination_cert = state / "unused"
        from pathlib import Path

        destination_cert = Path(args[args.index("-cert-file") + 1])
        destination_key = Path(args[args.index("-key-file") + 1])
        destination_cert.write_bytes(certificate(leaf_key, root_key, subject, issuer, tls.HOSTS))
        destination_key.write_bytes(key.read_bytes())

    monkeypatch.setattr(tls.subprocess, "run", generate)
    tls.ensure_certificate(state, prepare=True)
    archived = list(state.glob("https-previous-*/cert.pem"))
    assert len(archived) == 1 and archived[0].read_bytes() == old_cert
    assert key.stat().st_mode & 0o777 == 0o600


def test_environment_removes_ca_overrides_and_tls_bypasses(monkeypatch):
    monkeypatch.setenv("CAROOT", "/untrusted")
    monkeypatch.setenv("CURL_CA_BUNDLE", "/untrusted")
    monkeypatch.setenv("NODE_TLS_REJECT_UNAUTHORIZED", "0")
    env = tls.clean_environment()
    assert set(env) == {"HOME", "PATH", "LC_ALL"}


def test_endpoint_probe_uses_system_trust_and_fixed_url(monkeypatch):
    command = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(tls.subprocess, "run", command)
    tls.verify_endpoint()
    args = command.call_args.args[0]
    assert args[0] == "/usr/bin/curl"
    assert args[1] == "--disable"  # Ignore curlrc, including any insecure flags.
    assert not {"-k", "--insecure", "--cacert"}.intersection(args)
    assert args[-1] == "https://localhost:13000/native-sign-in"


def test_endpoint_trust_failure_never_succeeds(monkeypatch):
    monkeypatch.setattr(tls.subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 60)))
    with pytest.raises(tls.HttpsTrustError, match="system trust"):
        tls.verify_endpoint()


def test_missing_mkcert_does_not_run_installer(monkeypatch):
    monkeypatch.setattr(tls.shutil, "which", lambda *a, **k: None)
    command = Mock()
    monkeypatch.setattr(tls.subprocess, "run", command)
    with pytest.raises(tls.HttpsTrustError, match="independently approve"):
        tls.local_ca()
    command.assert_not_called()


def test_missing_ca_does_not_create_or_install_root(monkeypatch, tmp_path):
    monkeypatch.setattr(tls.shutil, "which", lambda *a, **k: "/synthetic/mkcert")
    command = Mock(return_value=SimpleNamespace(stdout=str(tmp_path), returncode=0))
    monkeypatch.setattr(tls.subprocess, "run", command)
    with pytest.raises(tls.HttpsTrustError, match="confirmation"):
        tls.local_ca()
    assert command.call_count == 1
    assert command.call_args.args[0] == ["/synthetic/mkcert", "-CAROOT"]
    assert list(tmp_path.iterdir()) == []


def test_existing_untrusted_ca_requires_operator_confirmation(monkeypatch, tmp_path):
    (tmp_path / "rootCA.pem").write_text("synthetic public certificate")
    monkeypatch.setattr(tls.shutil, "which", lambda *a, **k: "/synthetic/mkcert")
    command = Mock(return_value=SimpleNamespace(stdout=str(tmp_path), returncode=0))
    monkeypatch.setattr(tls.subprocess, "run", command)
    monkeypatch.setattr(tls, "system_trusted", lambda *a, **k: False)
    with pytest.raises(tls.HttpsTrustError, match="no trust-store change"):
        tls.local_ca()
    assert command.call_count == 1


def test_launcher_tls_failure_prevents_container_start(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from scripts import dev_greenfield

    for name in ("environment.json", "runtime-password", "setup-password"):
        (tmp_path / name).write_text("synthetic")
    monkeypatch.setattr(dev_greenfield.stack, "STATE", tmp_path)
    monkeypatch.setattr(
        dev_greenfield.https, "ensure_certificate", Mock(side_effect=tls.HttpsTrustError("not trusted"))
    )
    inspect = Mock()
    monkeypatch.setattr(dev_greenfield, "inventory", inspect)
    with pytest.raises(tls.HttpsTrustError):
        dev_greenfield.start(SimpleNamespace(check=False), Mock())
    inspect.assert_not_called()
