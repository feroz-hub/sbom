"""Stage 8 — signature validation (feature-flagged).

Default OFF. Enabled per-tenant via ``Settings.SBOM_SIGNATURE_VERIFICATION``.

When the flag is on:

* CycloneDX documents with a top-level ``signature`` block are verified
  against the JSF (JSON Signature Format) profile — ``alg``, ``publicKey``,
  and ``value`` are checked.
* SPDX documents may be accompanied by an external signature sidecar (the
  multipart endpoint accepts a second part named ``signature``); when present
  the bytes are verified via PGP / X.509.

In v1 the verification logic itself is intentionally a no-op stub: every
signature is reported as :data:`W113_SIGNATURE_NOT_PRESENT` if absent and as
"not yet implemented" if present and the flag is on. The contract — when
this stage runs, what codes it can emit, what its module path is — is
stable from day one so the rollout ADR can flip a single flag.
"""

from __future__ import annotations

from .. import errors as E
from ..context import ValidationContext

_STAGE = "signature"


def run(ctx: ValidationContext) -> ValidationContext:
    if not ctx.verify_signature:
        return ctx
    sbom = ctx.internal_model
    if sbom is None:
        return ctx

    if sbom.signature_block is None:
        ctx.report.add(
            E.W113_SIGNATURE_NOT_PRESENT,
            stage=_STAGE,
            path="signature",
            message="Signature verification is enabled but no signature block is present.",
            remediation=(
                "Embed a JSF signature (CycloneDX) or upload an external signature "
                "sidecar (SPDX)."
            ),
        )
        return ctx

    # Verification of an actual signature is deferred to the rollout ADR. We
    # emit a stable error so the contract is observable end-to-end without
    # the verification library yet pinned.
    ctx.report.add(
        E.E110_SIGNATURE_INVALID,
        stage=_STAGE,
        path="signature",
        message="Signature verification is enabled but the verifier is not yet implemented.",
        remediation=(
            "Disable SBOM_SIGNATURE_VERIFICATION until the rollout ADR ships, "
            "or omit the signature block."
        ),
    )
    return ctx
