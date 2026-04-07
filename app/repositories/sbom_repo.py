"""Repository for SBOMSource and SBOMType entities."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func, delete
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from ..models import SBOMSource, SBOMType


def _now_iso() -> str:
    """Return current UTC timestamp in ISO format without microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class SBOMRepository:
    """Repository for SBOM operations."""

    @staticmethod
    def get_sbom(db: Session, sbom_id: int) -> Optional[SBOMSource]:
        """Get a single SBOM by ID.

        Args:
            db: Database session
            sbom_id: SBOM ID

        Returns:
            SBOMSource or None if not found
        """
        return db.query(SBOMSource).filter(SBOMSource.id == sbom_id).first()

    @staticmethod
    def list_sboms(
        db: Session,
        project_id: Optional[int] = None,
        created_by: Optional[str] = None,
        sort_by: str = "id",
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> list[SBOMSource]:
        """List SBOMs with optional filtering and pagination.

        Args:
            db: Database session
            project_id: Filter by project ID
            created_by: Filter by creator
            sort_by: Column to sort by (default "id")
            sort_dir: Sort direction "asc" or "desc" (default "desc")
            page: Page number (1-indexed)
            page_size: Items per page

        Returns:
            List of SBOMSource objects
        """
        query = db.query(SBOMSource)

        if project_id is not None:
            query = query.filter(SBOMSource.project_id == project_id)

        if created_by is not None:
            query = query.filter(SBOMSource.created_by == created_by)

        # Apply sorting
        order_column = getattr(SBOMSource, sort_by, SBOMSource.id)
        if sort_dir.lower() == "asc":
            query = query.order_by(order_column.asc())
        else:
            query = query.order_by(order_column.desc())

        # Apply pagination
        offset = (page - 1) * page_size
        return query.offset(offset).limit(page_size).all()

    @staticmethod
    def create_sbom(db: Session, payload_dict: dict) -> SBOMSource:
        """Create a new SBOM.

        Sets created_on to current timestamp. Handles IntegrityError for
        duplicate names within the same project.

        Args:
            db: Database session
            payload_dict: Dictionary with SBOM fields

        Returns:
            Created SBOMSource object

        Raises:
            IntegrityError: If name already exists for the project
        """
        try:
            sbom = SBOMSource(
                **payload_dict,
                created_on=_now_iso(),
            )
            db.add(sbom)
            db.flush()
            return sbom
        except IntegrityError as e:
            db.rollback()
            raise e

    @staticmethod
    def update_sbom(db: Session, sbom_id: int, update_dict: dict) -> SBOMSource:
        """Update an existing SBOM.

        Args:
            db: Database session
            sbom_id: SBOM ID
            update_dict: Dictionary with fields to update

        Returns:
            Updated SBOMSource object

        Raises:
            ValueError: If SBOM not found
        """
        sbom = db.query(SBOMSource).filter(SBOMSource.id == sbom_id).first()
        if not sbom:
            raise ValueError(f"SBOM {sbom_id} not found")

        for key, value in update_dict.items():
            if hasattr(sbom, key):
                setattr(sbom, key, value)

        db.flush()
        return sbom

    @staticmethod
    def delete_sbom(db: Session, sbom_id: int) -> None:
        """Delete an SBOM and cascade to related entities.

        Cascades to:
        - SBOMComponent (components)
        - AnalysisFinding (findings)
        - AnalysisRun (runs)
        - SBOMAnalysisReport (reports)

        Args:
            db: Database session
            sbom_id: SBOM ID
        """
        sbom = db.query(SBOMSource).filter(SBOMSource.id == sbom_id).first()
        if not sbom:
            raise ValueError(f"SBOM {sbom_id} not found")

        # Delete in dependency order
        # AnalysisFinding depends on AnalysisRun
        # AnalysisRun depends on SBOMSource
        # SBOMComponent depends on SBOMSource
        # SBOMAnalysisReport depends on SBOMSource

        from ..models import (
            AnalysisFinding,
            AnalysisRun,
            SBOMComponent,
            SBOMAnalysisReport,
        )

        # Delete findings for runs associated with this SBOM
        db.execute(
            delete(AnalysisFinding).where(
                AnalysisFinding.run_id.in_(
                    db.query(AnalysisRun.id).filter(
                        AnalysisRun.sbom_id == sbom_id
                    )
                )
            )
        )

        # Delete runs
        db.execute(delete(AnalysisRun).where(AnalysisRun.sbom_id == sbom_id))

        # Delete components
        db.execute(
            delete(SBOMComponent).where(SBOMComponent.sbom_id == sbom_id)
        )

        # Delete reports
        db.execute(
            delete(SBOMAnalysisReport).where(
                SBOMAnalysisReport.sbom_id == sbom_id
            )
        )

        # Delete the SBOM itself
        db.delete(sbom)
        db.flush()

    @staticmethod
    def sbom_name_exists(db: Session, name: str) -> bool:
        """Check if an SBOM name already exists.

        Args:
            db: Database session
            name: SBOM name

        Returns:
            True if name exists, False otherwise
        """
        count = (
            db.query(func.count(SBOMSource.id))
            .filter(SBOMSource.name == name)
            .scalar()
        )
        return count > 0

    @staticmethod
    def list_sbom_types(db: Session) -> list[SBOMType]:
        """List all available SBOM types.

        Args:
            db: Database session

        Returns:
            List of SBOMType objects
        """
        return db.query(SBOMType).all()
