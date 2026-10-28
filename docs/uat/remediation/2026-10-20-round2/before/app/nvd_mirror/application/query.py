"""QueryMirror — single-CPE lookup against the local mirror."""

from __future__ import annotations

from ..domain.models import CveRecord
from ..ports import CveRepositoryPort


class QueryMirror:
    """Look up CVEs affecting a CPE 2.3 string.

    Thin wrapper around ``CveRepositoryPort.find_by_cpe`` so the Phase 5
    facade depends on a use case (and its narrow port) rather than the
    repo directly.
    """

    def __init__(self, *, cve_repo: CveRepositoryPort) -> None:
        self._cve_repo = cve_repo

    def execute(self, cpe23: str) -> list[CveRecord]:
        if not cpe23:
            return []
        return list(self._cve_repo.find_by_cpe(cpe23))
