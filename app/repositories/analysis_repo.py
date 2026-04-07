"""Repository for AnalysisRun, AnalysisFinding, and RunCache entities."""

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func, delete
from sqlalchemy.orm import Session

from ..models import AnalysisRun, AnalysisFinding, RunCache


def _now_iso() -> str:
    """Return current UTC timestamp in ISO format without microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class AnalysisRepository:
    """Repository for analysis run and finding operations."""

    @staticmethod
    def get_run(db: Session, run_id: int) -> Optional[AnalysisRun]:
        """Get a single analysis run by ID.

        Args:
            db: Database session
            run_id: Run ID

        Returns:
            AnalysisRun or None if not found
        """
        return db.query(AnalysisRun).filter(AnalysisRun.id == run_id).first()

    @staticmethod
    def list_runs(
        db: Session,
        sbom_id: Optional[int] = None,
        project_id: Optional[int] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        sort_by: str = "id",
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> list[AnalysisRun]:
        """List analysis runs with optional filtering and pagination.

        Args:
            db: Database session
            sbom_id: Filter by SBOM ID
            project_id: Filter by project ID
            status: Filter by status (e.g., "completed", "failed")
            source: Filter by source
            sort_by: Column to sort by (default "id")
            sort_dir: Sort direction "asc" or "desc" (default "desc")
            page: Page number (1-indexed)
            page_size: Items per page

        Returns:
            List of AnalysisRun objects
        """
        query = db.query(AnalysisRun)

        if sbom_id is not None:
            query = query.filter(AnalysisRun.sbom_id == sbom_id)

        if project_id is not None:
            query = query.filter(AnalysisRun.project_id == project_id)

        if status is not None:
            query = query.filter(AnalysisRun.status == status)

        if source is not None:
            query = query.filter(AnalysisRun.source == source)

        # Apply sorting
        order_column = getattr(AnalysisRun, sort_by, AnalysisRun.id)
        if sort_dir.lower() == "asc":
            query = query.order_by(order_column.asc())
        else:
            query = query.order_by(order_column.desc())

        # Apply pagination
        offset = (page - 1) * page_size
        return query.offset(offset).limit(page_size).all()

    @staticmethod
    def create_run(db: Session, **kwargs) -> AnalysisRun:
        """Create a new analysis run.

        Flushes but does not commit, allowing the caller to add related
        findings and then commit together.

        Args:
            db: Database session
            **kwargs: Fields for AnalysisRun

        Returns:
            Created AnalysisRun object (unflushed)
        """
        run = AnalysisRun(**kwargs)
        db.add(run)
        db.flush()
        return run

    @staticmethod
    def create_finding(db: Session, **kwargs) -> AnalysisFinding:
        """Create a new analysis finding.

        Adds but does not flush, allowing the caller to batch multiple
        findings and flush together.

        Args:
            db: Database session
            **kwargs: Fields for AnalysisFinding

        Returns:
            Created AnalysisFinding object (unadded but staged)
        """
        finding = AnalysisFinding(**kwargs)
        db.add(finding)
        return finding

    @staticmethod
    def list_findings(
        db: Session,
        run_id: int,
        severity: Optional[str] = None,
        page: int = 1,
        page_size: int = 200,
    ) -> list[AnalysisFinding]:
        """List findings for a specific run with optional filtering.

        Args:
            db: Database session
            run_id: Run ID
            severity: Filter by severity level
            page: Page number (1-indexed)
            page_size: Items per page

        Returns:
            List of AnalysisFinding objects
        """
        query = db.query(AnalysisFinding).filter(
            AnalysisFinding.run_id == run_id
        )

        if severity is not None:
            query = query.filter(AnalysisFinding.severity == severity)

        # Apply pagination
        offset = (page - 1) * page_size
        return query.offset(offset).limit(page_size).all()

    @staticmethod
    def store_run_cache(
        db: Session,
        run_json: str,
        source: Optional[str] = None,
        sbom_id: Optional[int] = None,
    ) -> int:
        """Store run results in cache and commit.

        Args:
            db: Database session
            run_json: JSON string of run results
            source: Optional source identifier
            sbom_id: Optional SBOM ID

        Returns:
            ID of created RunCache entry
        """
        cache_entry = RunCache(
            run_json=run_json,
            source=source,
            sbom_id=sbom_id,
            cached_at=_now_iso(),
        )
        db.add(cache_entry)
        db.commit()
        return cache_entry.id

    @staticmethod
    def load_run_cache(db: Session, run_id: int) -> Optional[dict]:
        """Load and parse run results from cache.

        Args:
            db: Database session
            run_id: Run cache ID

        Returns:
            Parsed JSON dict or None if not found
        """
        cache_entry = (
            db.query(RunCache).filter(RunCache.id == run_id).first()
        )
        if not cache_entry:
            return None

        try:
            return json.loads(cache_entry.run_json)
        except (json.JSONDecodeError, TypeError):
            return None
