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
from scripts import dev


class _CanonicalTlsSurface:
    """Patch the real canonical class methods and their module dependencies.

    The adapter is a class whose subprocess/os dependencies live in scripts.dev.
    Writes patch the real implementation rather than a copied TLS module.
    """

    def __getattr__(self, name):
        if hasattr(dev.LocalHttps, name):
            return getattr(dev.LocalHttps, name)
        return getattr(dev, name)

    def __setattr__(self, name, value):
        target = dev.LocalHttps if hasattr(dev.LocalHttps, name) else dev
        setattr(target, name, value)


tls = _CanonicalTlsSurface()


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
    assert metadata["system_trusted"] is True
    assert metadata["macos_trusted"] is (tls.sys.platform == "darwin")
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
    monkeypatch.setattr(tls.sys, "platform", "darwin")
    monkeypatch.setenv("CAROOT", "/untrusted")
    monkeypatch.setenv("CURL_CA_BUNDLE", "/untrusted")
    monkeypatch.setenv("NODE_TLS_REJECT_UNAUTHORIZED", "0")
    env = tls.clean_environment()
    assert set(env) == {"HOME", "PATH", "LC_ALL"}


def test_endpoint_probe_uses_system_trust_and_fixed_url(monkeypatch):
    monkeypatch.setattr(tls.sys, "platform", "darwin")
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


    for name in ("environment.json", "runtime-password", "setup-password"):
        (tmp_path / name).write_text("synthetic")
    monkeypatch.setattr(dev.GreenfieldStack, "STATE", tmp_path)
    monkeypatch.setattr(
        dev.LocalHttps, "ensure_certificate", Mock(side_effect=tls.HttpsTrustError("not trusted"))
    )
    inspect = Mock()
    monkeypatch.setattr(dev.GreenfieldProfile, "inventory", inspect)
    with pytest.raises(tls.HttpsTrustError):
        dev.GreenfieldProfile.start(SimpleNamespace(check=False), Mock())
    inspect.assert_not_called()


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_platform_environment_keeps_required_paths_but_removes_tls_bypasses(monkeypatch, platform):
    monkeypatch.setattr(tls.sys, "platform", platform)
    for key in ("CAROOT", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "NODE_TLS_REJECT_UNAUTHORIZED", "OPENSSL_CONF"):
        monkeypatch.setenv(key, "untrusted")
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\Developer\AppData\Local")
    env = tls.clean_environment()
    assert not set(env).intersection({"CAROOT", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "NODE_TLS_REJECT_UNAUTHORIZED", "OPENSSL_CONF"})
    if platform == "win32":
        assert env["SYSTEMROOT"] == r"C:\Windows"
        assert "LOCALAPPDATA" in env


def test_linux_verifies_against_native_default_trust_without_ca_override(monkeypatch, tmp_path):
    monkeypatch.setattr(tls.sys, "platform", "linux")
    monkeypatch.setattr(tls.shutil, "which", lambda *a, **k: "/usr/bin/openssl")
    command = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(tls.subprocess, "run", command)
    assert tls.system_trusted(tmp_path / "cert.pem", hostname="localhost") is True
    args = command.call_args.args[0]
    assert args[:2] == ["/usr/bin/openssl", "verify"]
    assert args[2:6] == ["-purpose", "sslserver", "-verify_hostname", "localhost"]
    assert not {"-CAfile", "-CApath", "-CAstore"}.intersection(args)
    assert "SSL_CERT_FILE" not in command.call_args.kwargs["env"]


def test_linux_untrusted_certificate_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(tls.sys, "platform", "linux")
    monkeypatch.setattr(tls.shutil, "which", lambda *a, **k: "/usr/bin/openssl")
    monkeypatch.setattr(tls.subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 2)))
    assert tls.system_trusted(tmp_path / "cert.pem") is False


def test_linux_missing_trust_tool_is_actionable_and_does_not_install(monkeypatch, tmp_path):
    monkeypatch.setattr(tls.sys, "platform", "linux")
    monkeypatch.setattr(tls.shutil, "which", lambda *a, **k: None)
    command = Mock()
    monkeypatch.setattr(tls.subprocess, "run", command)
    with pytest.raises(tls.HttpsTrustError, match="openssl package"):
        tls.system_trusted(tmp_path / "cert.pem")
    command.assert_not_called()


def _mock_windows_roots(monkeypatch, root, *, trusted=True):
    monkeypatch.setattr(tls.sys, "platform", "win32")
    monkeypatch.setattr(tls, "_windows_access", lambda *a, **k: None)
    der = x509.load_pem_x509_certificate(root.read_bytes()).public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(tls.ssl, "enum_certificates", lambda store: [(der, "x509_asn", trusted)], raising=False)


def test_windows_requires_exact_root_in_native_store(pair, monkeypatch):
    _, cert, _, root, *_ = pair
    _mock_windows_roots(monkeypatch, root)
    assert tls._windows_system_trusted(root) is True
    assert tls._windows_system_trusted(cert, hostname="localhost") is True
    assert tls._windows_system_trusted(cert) is False
    assert tls._windows_system_trusted(cert, hostname="other.local") is False


def test_windows_rejects_root_without_server_auth_trust(pair, monkeypatch):
    _, cert, _, root, *_ = pair
    _mock_windows_roots(monkeypatch, root, trusted={"1.3.6.1.5.5.7.3.3"})
    assert tls._windows_system_trusted(root) is False
    assert tls._windows_system_trusted(cert, hostname="localhost") is False


def test_windows_rejects_different_signer_even_with_same_issuer_name(pair, monkeypatch):
    _, cert, _, root, leaf_key, _, subject, issuer = pair
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert.write_bytes(certificate(leaf_key, other, subject, issuer, tls.HOSTS))
    _mock_windows_roots(monkeypatch, root)
    assert tls._windows_system_trusted(cert, hostname="localhost") is False


def test_windows_native_store_failure_is_actionable(pair, monkeypatch):
    _, cert, _, root, *_ = pair
    _mock_windows_roots(monkeypatch, root)
    monkeypatch.setattr(tls.ssl, "enum_certificates", Mock(side_effect=OSError("unavailable")), raising=False)
    with pytest.raises(tls.HttpsTrustError, match="native ROOT store"):
        tls._windows_system_trusted(cert, hostname="localhost")


def _mock_windows_acl(monkeypatch, *, category=None):
    from scripts import dev_windows_acl

    monkeypatch.setattr(tls.sys, "platform", "win32")
    inspect = Mock(
        side_effect=dev_windows_acl.AclVerificationError("GetSecurityInfo", 5, category) if category else None
    )
    monkeypatch.setattr(dev_windows_acl, "verify_access", inspect)
    monkeypatch.setattr(
        tls.subprocess, "run", Mock(side_effect=AssertionError("ACL inspection launched a shell helper"))
    )
    return inspect


def test_windows_accepts_current_user_private_acl_without_changing_it(monkeypatch, tmp_path):
    inspect = _mock_windows_acl(monkeypatch)
    tls._windows_access(tmp_path, private=True)
    inspect.assert_called_once_with(tmp_path.absolute(), private=True)


@pytest.mark.parametrize("category", ["OWNER_MISMATCH", "NULL_SECURITY_METADATA", "UNTRUSTED_GRANT"])
def test_windows_rejects_unowned_null_or_public_private_acl(monkeypatch, tmp_path, category):
    _mock_windows_acl(monkeypatch, category=category)
    with pytest.raises(tls.HttpsTrustError, match="no ACL was changed"):
        tls._windows_access(tmp_path, private=True)


def test_windows_public_cert_can_be_readable_but_not_writable_by_everyone(monkeypatch, tmp_path):
    inspect = _mock_windows_acl(monkeypatch)
    tls._windows_access(tmp_path, private=False)
    inspect.assert_called_once_with(tmp_path.absolute(), private=False)
    _mock_windows_acl(monkeypatch, category="UNTRUSTED_GRANT")
    with pytest.raises(tls.HttpsTrustError, match="private ACL"):
        tls._windows_access(tmp_path, private=False)


def test_windows_acl_probe_failure_is_fail_closed(monkeypatch, tmp_path):
    _mock_windows_acl(monkeypatch, category="API_FAILURE")
    with pytest.raises(tls.HttpsTrustError, match="winerror=5"):
        tls._windows_access(tmp_path, private=True)


def test_windows_reparse_directory_is_rejected_before_acl_probe(monkeypatch):
    monkeypatch.setattr(tls.sys, "platform", "win32")
    path = Mock()
    path.lstat.return_value = SimpleNamespace(st_mode=0o40700, st_file_attributes=0x400)
    check = Mock()
    monkeypatch.setattr(tls, "_windows_access", check)
    with pytest.raises(tls.HttpsTrustError, match="reparse|nonsymlink"):
        tls.private_directory(path)
    check.assert_not_called()


@pytest.mark.parametrize("platform,binary", [("linux", "/usr/bin/curl"), ("win32", "curl.exe")])
def test_endpoint_probe_is_portable_and_still_uses_system_trust(monkeypatch, platform, binary):
    monkeypatch.setattr(tls.sys, "platform", platform)
    monkeypatch.setattr(tls.shutil, "which", lambda *a, **k: binary)
    command = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(tls.subprocess, "run", command)
    tls.verify_endpoint()
    args = command.call_args.args[0]
    assert args[0] == binary
    assert args[1] == "--disable"
    assert args[args.index("--output") + 1] == os.devnull
    assert not {"-k", "--insecure", "--cacert"}.intersection(args)
