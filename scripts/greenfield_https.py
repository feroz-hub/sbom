"""macOS greenfield development HTTPS; never installs a CA or modifies trust.

Only an existing, system-trusted mkcert CA may issue a leaf certificate here.
Production TLS and the legacy development launcher are deliberately separate.
"""

from __future__ import annotations

import argparse
import os
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

HOSTS = ("localhost", "127.0.0.1", "::1")


class HttpsTrustError(RuntimeError):
    """Actionable, nonsecret trust diagnostic suitable for the launcher."""


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise HttpsTrustError("HTTPS state must be an owned, nonsymlink private directory (0700)")


def read_file(path, *, key=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise HttpsTrustError("HTTPS material must be owned, regular, single-link files")
        if key and stat.S_IMODE(info.st_mode) != 0o600:
            raise HttpsTrustError("HTTPS private key must have mode 0600")
        data = source.read(131073)
        if len(data) > 131072:
            raise HttpsTrustError("Unexpected HTTPS material size")
        return data


def clean_environment():
    # Never inherit CAROOT, CURL_CA_BUNDLE, SSL_CERT_FILE, proxy or TLS bypasses.
    return {"HOME": str(Path.home()), "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"}


def system_trusted(cert, *, hostname=None):
    if sys.platform != "darwin":
        raise HttpsTrustError("Automated greenfield CA trust verification currently requires macOS Keychain")
    args = ["/usr/bin/security", "verify-cert", "-c", str(cert), "-p", "ssl" if hostname else "basic"]
    if hostname:
        args += ["-s", hostname]
    return subprocess.run(args, env=clean_environment(), capture_output=True, timeout=15).returncode == 0


def local_ca():
    executable = shutil.which("mkcert", path=clean_environment()["PATH"])
    if not executable:
        raise HttpsTrustError("mkcert is required. Install it, then independently approve local CA trust setup.")
    result = subprocess.run(
        [executable, "-CAROOT"], env=clean_environment(), capture_output=True, text=True, check=True, timeout=10
    )
    root = Path(result.stdout.strip()) / "rootCA.pem"
    if not root.is_file() or root.is_symlink():
        raise HttpsTrustError(
            "No existing mkcert CA. Operator confirmation is required before running mkcert -install."
        )
    read_file(root)
    if not system_trusted(root):
        raise HttpsTrustError(
            "Local mkcert CA is not trusted by macOS. Operator confirmation is required before mkcert -install; "
            "no trust-store change was made."
        )
    return executable, root


def validate_pair(cert_path, key_path, root_path):
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization

    cert = x509.load_pem_x509_certificate(read_file(cert_path))
    root = x509.load_pem_x509_certificate(read_file(root_path))
    key = serialization.load_pem_private_key(read_file(key_path, key=True), password=None)
    now = datetime.now(UTC)
    if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now + timedelta(days=7):
        raise HttpsTrustError(
            "Local HTTPS certificate is not valid or expires within seven days; prepare a renewed leaf"
        )
    try:
        sans = {str(item.value) for item in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value}
        if sans != set(HOSTS):
            raise ValueError()
        cert.verify_directly_issued_by(root)
        public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if cert.public_key().public_bytes(*public_format) != key.public_key().public_bytes(*public_format):
            raise ValueError()
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound) as exc:
        raise HttpsTrustError(
            "HTTPS leaf must match its key and the trusted local CA, covering exactly localhost/IPv4/IPv6"
        ) from exc
    if not system_trusted(cert_path, hostname="localhost"):
        raise HttpsTrustError("HTTPS certificate is not trusted by macOS for localhost; browser readiness is blocked")
    return {
        "certificate_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "issuer_sha256": root.fingerprint(hashes.SHA256()).hex(),
        "issuer": cert.issuer.rfc4514_string(),
        "sans": sorted(sans),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "macos_trusted": True,
    }


def ensure_certificate(state, *, prepare=False):
    if prepare:
        state.mkdir(mode=0o700, exist_ok=True)
    private_directory(state)
    executable, root = local_ca()
    cert, key = state / "cert.pem", state / "cert-key.pem"
    # Reject unsafe existing files even when replacing an obsolete leaf.
    for path, is_key in ((cert, False), (key, True)):
        if path.exists() or path.is_symlink():
            read_file(path, key=is_key)
    try:
        metadata = validate_pair(cert, key, root)
        return cert, key, root, metadata
    except (HttpsTrustError, FileNotFoundError, ValueError) as exc:
        if not prepare:
            raise HttpsTrustError(
                "HTTPS trust check failed. Run python3 -m scripts.greenfield_https prepare after reviewing the "
                "existing trusted CA; no application passwords or trust settings were changed."
            ) from exc
    # Generate only a leaf. No -install, no trust mutation, no CA-key copy.
    with tempfile.TemporaryDirectory(prefix="https-staging-", dir=state) as directory:
        staging = Path(directory)
        candidate_cert, candidate_key = staging / "cert.pem", staging / "cert-key.pem"
        old_mask = os.umask(0o077)
        try:
            subprocess.run(
                [executable, "-cert-file", str(candidate_cert), "-key-file", str(candidate_key), *HOSTS],
                env=clean_environment(),
                capture_output=True,
                check=True,
                timeout=30,
            )
        finally:
            os.umask(old_mask)
        candidate_key.chmod(0o600)
        candidate_cert.chmod(0o600)
        metadata = validate_pair(candidate_cert, candidate_key, root)
        # Retain the previous pair privately; never overwrite historical keys.
        archive = Path(tempfile.mkdtemp(prefix="https-previous-", dir=state))
        for path in (cert, key):
            if path.exists():
                path.rename(archive / path.name)
        candidate_key.rename(key)
        candidate_cert.rename(cert)
    return cert, key, root, metadata


def client_context(state):
    _, _, root, _ = ensure_certificate(state)
    # Explicit CA for Python builds that do not automatically read Keychain.
    # macOS trust was independently required above; this is not a trust bypass.
    return ssl.create_default_context(cafile=str(root))


def verify_endpoint():
    result = subprocess.run(
        [
            "/usr/bin/curl",
            "--disable",
            "--noproxy",
            "*",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "5",
            "--max-time",
            "10",
            "--output",
            "/dev/null",
            "https://localhost:13000/native-sign-in",
        ],
        env=clean_environment(),
        capture_output=True,
        timeout=15,
    )
    if result.returncode:
        raise HttpsTrustError(
            "Served HTTPS failed default system trust/HTTP verification. Check certificate selection and Chrome trust; "
            "no TLS bypass is permitted."
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "prepare", "verify-served"))
    args = parser.parse_args()
    state = Path.home() / ".sbom-greenfield-uuid"
    _, _, _, metadata = ensure_certificate(state, prepare=args.action == "prepare")
    if args.action == "verify-served":
        verify_endpoint()
    print("HTTPS certificate trusted by macOS:", metadata["certificate_sha256"])
    print("SANs:", ", ".join(metadata["sans"]))
    print("No root CA or trust-store settings were installed or changed.")


if __name__ == "__main__":
    try:
        main()
    except HttpsTrustError as exc:
        raise SystemExit(str(exc)) from None
