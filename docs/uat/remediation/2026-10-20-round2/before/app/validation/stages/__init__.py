"""Pipeline stages — each module exposes ``run(ctx) -> ctx``."""

# Stage names → 1-based ordinal in the documented 8-stage pipeline.
# The orchestrator's ``ctx.report.entries[i].stage`` field carries the
# name; UIs that want to render "Stage 4 · Semantic" look up the number
# here so the canonical numbering lives in one place.
STAGE_NUMBERS: dict[str, int] = {
    "ingress": 1,
    "detect": 2,
    "schema": 3,
    "semantic": 4,
    "integrity": 5,
    "security": 6,
    "ntia": 7,
    "signature": 8,
}

STAGE_LABELS: dict[str, str] = {
    "ingress": "Ingress",
    "detect": "Format detection",
    "schema": "Schema",
    "semantic": "Semantic",
    "integrity": "Cross-reference integrity",
    "security": "Security",
    "ntia": "NTIA minimum elements",
    "signature": "Signature",
}
