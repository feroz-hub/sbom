"""
Repository ports (Protocols) for persistence — implemented by ``app.repositories``.

Use these in type hints for services under test with fakes; production wiring
uses concrete ``SBOMRepository`` / ``AnalysisRepository`` classes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sqlalchemy.orm import Session

from ..models import AnalysisRun, SBOMSource


@runtime_checkable
class SBOMRepositoryPort(Protocol):
    """Subset of SBOM data access used by services and tests."""

    @staticmethod
    def get_sbom(db: Session, sbom_id: int) -> SBOMSource | None: ...

    @staticmethod
    def list_sboms(
        db: Session,
        project_id: int | None = None,
        created_by: str | None = None,
        sort_by: str = "id",
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> list[SBOMSource]: ...

    @staticmethod
    def create_sbom(db: Session, payload_dict: dict) -> SBOMSource: ...


@runtime_checkable
class AnalysisRepositoryPort(Protocol):
    """Analysis runs — minimal port for extension and unit-test doubles."""

    @staticmethod
    def get_run(db: Session, run_id: int) -> AnalysisRun | None: ...

    @staticmethod
    def list_runs(
        db: Session,
        sbom_id: int | None = None,
        project_id: int | None = None,
        status: str | None = None,
        source: str | None = None,
        sort_by: str = "id",
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> list[AnalysisRun]: ...
