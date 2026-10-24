"""Stage 4 — semantic validation for SPDX 3.0 (deferred in v1).

The structural shape of SPDX 3.0 (JSON-LD with ``@graph`` / ``@context``
elements) differs enough from SPDX 2.x that the 2.x semantic checks would
not apply directly. Stage 2 (detect) already rejects SPDX 3.0 documents
with :data:`SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED`, so this module exists
to (a) make the dispatch in :mod:`app.validation.pipeline` total and
(b) serve as the future home of 3.0 semantic checks.

Adding 3.0 support later is a three-step PR:

  1. Vendor the SPDX 3.0 schema and update
     :mod:`app.validation.schemas.spdx.SOURCE`.
  2. Replace the :data:`E013` reject in :mod:`detect` with a real branch
     that sets ``ctx.spec_version = "SPDX-3.0"``.
  3. Implement the semantic checks here.

No public API change is required.
"""

from __future__ import annotations

from .. import errors as E
from ..context import ValidationContext

_STAGE = "semantic"


def run(ctx: ValidationContext) -> ValidationContext:
    # Defensive — detect should already have rejected SPDX 3.0 documents.
    ctx.report.add(
        E.E013_SPEC_VERSION_UNSUPPORTED,
        stage=_STAGE,
        path="",
        message="SPDX 3.0 semantic validation is not implemented in v1.",
        remediation="Re-export as SPDX 2.3.",
    )
    return ctx
