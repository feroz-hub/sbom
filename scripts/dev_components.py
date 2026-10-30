"""Project child environments without changing parent lifecycle metadata."""

from __future__ import annotations

import json
import ntpath
import os
import subprocess
from pathlib import Path

if __package__:
    from . import dev_config, dev_environment, dev_frontend, dev_private
else:
    import dev_config
    import dev_environment
    import dev_frontend
    import dev_private

# ECMAScript String.trim(), matching the existing BFF CA-path resolver.
_BFF_WHITESPACE = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"


def _absolute(value, base):
    if Path(value).is_absolute() or ntpath.isabs(value):
        return value
    return str((Path(base) / value).absolute())


def compiler_guard(launcher):
    """Return the reviewed internal preload; inspecting it never executes Node."""
    path = launcher.ROOT / "scripts/dev_next_guard.cjs"
    try:
        dev_private.validate_parent(path, launcher.ROOT)
        if not dev_environment.bounded_read_bytes(path, limit=32768):
            raise ValueError()
    except (OSError, ValueError, dev_private.PrivateFileError):
        raise launcher.SetupError(
            "FRONTEND_GUARD_REQUIRED: restore the reviewed launcher compiler-download guard before starting."
        ) from None
    return path


def review_source_environment(launcher, environment, profile):
    """Refuse to discard supported Next-only fallback settings silently."""
    if profile != "legacy":
        return  # The preserved Greenfield workspace already excluded dotenv.
    try:
        dev_private.validate_parent(launcher.ROOT / "frontend/.env", launcher.ROOT, allow_missing=True)
    except dev_private.PrivateFileError:
        raise launcher.SetupError(
            "FRONTEND_SOURCE_CONFIGURATION_UNVERIFIED: review redirected source parents; no private file was read."
        ) from None
    mode = "test" if environment.get("NODE_ENV") == "test" else "development"
    names = [f".env.{mode}.local", *([] if mode == "test" else [".env.local"]), f".env.{mode}", ".env"]
    canonical = str.casefold if launcher.sys.platform == "win32" else str
    seen = {canonical(key) for key in environment}
    for name in names:
        path = launcher.ROOT / "frontend" / name
        if not path.exists() and not path.is_symlink():
            continue
        try:
            values = dev_config.parse_dotenv(dev_environment.bounded_read_text(path))
        except (OSError, ValueError):
            raise launcher.SetupError(
                "FRONTEND_SOURCE_CONFIGURATION_UNVERIFIED: review existing Next environment files without deleting or rewriting them."
            ) from None
        effective = {key: value for key, value in values.items() if canonical(key) not in seen}
        seen.update(canonical(key) for key in values)
        known = dev_config.APPROVED_FRONTEND_SETTINGS | {"NODE_TLS_REJECT_UNAUTHORIZED"}
        if effective.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
            raise launcher.SetupError(
                "TLS_VERIFICATION_REQUIRED: review the TLS verification bypass in Next-only configuration before starting."
            )
        if any(key.upper() in known and key not in known for key in effective):
            raise launcher.SetupError(
                "FRONTEND_SOURCE_CONFIGURATION_REVIEW_REQUIRED: review canonical setting names in Next-only configuration; no value was renamed or adopted."
            )
        defaults = {"NEXT_TELEMETRY_DISABLED": "1"}
        if any(
            key in dev_config.APPROVED_FRONTEND_SETTINGS
            and key not in environment
            and (value or key in {"SSL_CERT_FILE", "SSL_CERT_DIR"})
            and value != defaults.get(key)
            for key, value in effective.items()
        ):
            raise launcher.SetupError(
                "FRONTEND_SOURCE_CONFIGURATION_REVIEW_REQUIRED: a Next-only file supplies settings absent from the authoritative profile. "
                "Review the approved configuration source before starting; no private file was changed or implicitly adopted."
            )


def process_environment(launcher, name, environment, cwd, *, profile=None):
    """Return only the role's inputs; preserve the caller's dict for ownership."""
    roles = {
        "API": "api",
        "Frontend": "frontend",
        "Celery worker": "worker",
        "Celery reports worker": "worker",
        "Celery Beat": "beat",
        "Worker": "worker",
    }
    if name not in roles:
        raise launcher.SetupError("COMPONENT_CONFIGURATION_REQUIRED: select a declared launcher component.")
    role = roles[name]
    try:
        projected = dict(dev_config.component_environment(environment, role))
    except dev_config.ConfigurationError as error:
        raise launcher.SetupError(str(error)) from None
    if role != "frontend":
        return projected
    profile = profile or environment.get("SBOM_DEV_PROFILE") or launcher.ACTIVE_PROFILE
    workspace = dev_frontend.require_workspace(launcher, profile)
    if Path(cwd).absolute() != workspace.absolute():
        raise launcher.SetupError(
            "FRONTEND_WORKSPACE_REQUIRED: Node must run in the prepared environment-free workspace."
        )
    review_source_environment(launcher, environment, profile)
    original = launcher.ROOT / "frontend" if profile == "legacy" else launcher.GreenfieldStack.STATE / "frontend"
    default_key = (
        launcher.ROOT / "frontend/certificates/localhost-key.pem"
        if profile == "legacy"
        else launcher.GreenfieldStack.STATE / "cert-key.pem"
    )
    projected["AUTH_TRANSACTION_KEY_FILE"] = _absolute(
        projected.get("AUTH_TRANSACTION_KEY_FILE") or str(default_key), original
    )
    if "HCL_IAM_CA_BUNDLE" in projected:
        value = projected["HCL_IAM_CA_BUNDLE"].strip(_BFF_WHITESPACE)
        projected["HCL_IAM_CA_BUNDLE"] = _absolute(value, original) if value else ""
    for key in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"):
        if projected.get(key):
            projected[key] = _absolute(projected[key], original)
    if "SSL_CERT_DIR" in projected:
        directories = projected["SSL_CERT_DIR"].split(os.pathsep)
        if any(not value for value in directories):
            raise launcher.SetupError(
                "TLS_CA_PATH_REVIEW_REQUIRED: review ambiguous OpenSSL CA directory entries; no trust setting was discarded."
            )
        projected["SSL_CERT_DIR"] = os.pathsep.join(_absolute(value, original) for value in directories)
    guard = compiler_guard(launcher)
    # User NODE_OPTIONS passed the pure allowlist before this trusted internal
    # preload is appended. Next's forked children inherit the same denial.
    projected["NODE_OPTIONS"] = (
        projected.get("NODE_OPTIONS", "").strip() + " --require " + json.dumps(guard.as_posix())
    ).strip()
    return projected


def verify_compiler(launcher, environment, workspace, *, profile):
    """Load the existing native binding only; never invoke Next's downloader.

    This is a startup/build probe, not part of read-only diagnose. The probe
    receives transport metadata only and owns its original Popen handle.
    """
    selected = process_environment(launcher, "Frontend", environment, workspace, profile=profile)
    names = {
        "HOME",
        "PATH",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
    }
    probe_env = {key: value for key, value in selected.items() if key in names}
    probe_env.update(CI="1", NEXT_TELEMETRY_DISABLED="1", NEXT_DISABLE_SWC_WASM="1")
    script = "const p=require('node:path');let ready=false;try{const root=process.argv[1],table=require(p.join(root,'next/dist/compiled/@napi-rs/triples')).platformArchTriples;for(const t of (table[process.platform]?.[process.arch]||[])){if((process.platform==='win32'&&t.abi!=='msvc')||(process.platform==='linux'&&t.abi==='gnux32'))continue;try{require(p.join(root,'@next/swc-'+t.platformArchABI));ready=true;break}catch{}}}catch{}process.stdout.write(JSON.stringify({ready}));"
    child = None
    try:
        child = subprocess.Popen(
            [
                str(launcher.GreenfieldStack.node_binary()),
                "--require",
                str(compiler_guard(launcher)),
                "-e",
                script,
                str(launcher.ROOT / "frontend/node_modules"),
            ],
            cwd=workspace,
            env=probe_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output, error_output = child.communicate(timeout=8)
        if child.returncode and isinstance(error_output, str) and error_output.startswith("FRONTEND_GUARD_REQUIRED"):
            raise launcher.SetupError(
                "FRONTEND_GUARD_REQUIRED: restore the reviewed launcher and pinned Next installation before starting; no dependency download was allowed."
            )
        payload = json.loads(output) if len(output) <= 128 else None
        if (
            child.returncode != 0
            or not isinstance(payload, dict)
            or set(payload) != {"ready"}
            or payload["ready"] is not True
        ):
            raise ValueError()
    except BaseException as error:
        unfinished = child is not None
        if child is not None:
            try:
                unfinished = child.poll() is None
            except (OSError, KeyboardInterrupt):
                pass  # Original ownership is still held even if polling fails.
        if unfinished:
            try:
                child.kill()  # Original owned handle only; never a saved PID or tree.
                child.communicate(timeout=3)
                if child.returncode is None:
                    raise OSError()
            except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyboardInterrupt):
                raise launcher.SetupError(
                    f"FRONTEND_PROBE_CLEANUP_UNCONFIRMED: owned Node probe PID {child.pid}; inspect it before retrying. No unrelated PID was signalled."
                ) from None
        if isinstance(error, subprocess.TimeoutExpired):
            raise launcher.SetupError(
                "FRONTEND_COMPILER_TIMEOUT: the owned native compiler probe was stopped; review Node/dependency setup before starting."
            ) from None
        if isinstance(error, (OSError, ValueError, TypeError)):
            raise launcher.SetupError(
                "FRONTEND_NATIVE_BINDING_REQUIRED: review the selected Node architecture and the setup --repair-dependencies plan; no compiler download or installation was attempted."
            ) from None
        raise
