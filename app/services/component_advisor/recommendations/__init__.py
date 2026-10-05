"""Recommendation work items, triggers and candidate discovery (spec Steps 5–8).

Pure modules: :mod:`.workflow` (states, transitions, triggers) and
:mod:`.version_discovery` (same-family candidate evaluation). The service
that persists work items is :mod:`.service`.

Advisory only (spec §1.1): nothing here upgrades, edits or replaces a
dependency, a manifest, source code or an SBOM.
"""
