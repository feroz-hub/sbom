"""Repository for Projects entity."""

from sqlalchemy import delete
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, Projects, SBOMSource


class ProjectRepository:
    """Repository for project operations."""

    @staticmethod
    def get_project(db: Session, project_id: int) -> Projects | None:
        """Get a single project by ID.

        Args:
            db: Database session
            project_id: Project ID

        Returns:
            Projects or None if not found
        """
        return db.query(Projects).filter(Projects.id == project_id).first()

    @staticmethod
    def list_projects(db: Session) -> list[Projects]:
        """List all projects.

        Args:
            db: Database session

        Returns:
            List of Projects objects
        """
        return db.query(Projects).order_by(Projects.id.desc()).all()

    @staticmethod
    def create_project(db: Session, payload_dict: dict) -> Projects:
        """Create a new project.

        Args:
            db: Database session
            payload_dict: Dictionary with project fields

        Returns:
            Created Projects object
        """
        project = Projects(**payload_dict)
        db.add(project)
        db.flush()
        return project

    @staticmethod
    def update_project(db: Session, project_id: int, update_dict: dict) -> Projects:
        """Update an existing project.

        Args:
            db: Database session
            project_id: Project ID
            update_dict: Dictionary with fields to update

        Returns:
            Updated Projects object

        Raises:
            ValueError: If project not found
        """
        project = db.query(Projects).filter(Projects.id == project_id).first()
        if not project:
            raise ValueError(f"Project {project_id} not found")

        for key, value in update_dict.items():
            if hasattr(project, key):
                setattr(project, key, value)

        db.flush()
        return project

    @staticmethod
    def delete_project(db: Session, project_id: int) -> None:
        """Delete a project and cascade to related entities.

        Cascades to:
        - SBOMSource (SBOMs in the project)
        - AnalysisRun (runs for SBOMs in the project)
        - AnalysisFinding (findings from runs)
        - All components and reports associated

        Args:
            db: Database session
            project_id: Project ID
        """
        project = db.query(Projects).filter(Projects.id == project_id).first()
        if not project:
            raise ValueError(f"Project {project_id} not found")

        from ..models import (
            SBOMAnalysisReport,
            SBOMComponent,
        )

        # Get all SBOMs for this project
        sbom_ids = db.query(SBOMSource.id).filter(SBOMSource.project_id == project_id).all()
        sbom_ids = [s[0] for s in sbom_ids]

        if sbom_ids:
            # Delete findings for runs associated with these SBOMs
            db.execute(
                delete(AnalysisFinding).where(
                    AnalysisFinding.run_id.in_(db.query(AnalysisRun.id).filter(AnalysisRun.sbom_id.in_(sbom_ids)))
                )
            )

            # Delete runs
            db.execute(delete(AnalysisRun).where(AnalysisRun.sbom_id.in_(sbom_ids)))

            # Delete components
            db.execute(delete(SBOMComponent).where(SBOMComponent.sbom_id.in_(sbom_ids)))

            # Delete reports
            db.execute(delete(SBOMAnalysisReport).where(SBOMAnalysisReport.sbom_id.in_(sbom_ids)))

            # Delete SBOMs
            db.execute(delete(SBOMSource).where(SBOMSource.project_id == project_id))

        # Delete the project itself
        db.delete(project)
        db.flush()
