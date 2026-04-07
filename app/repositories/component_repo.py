"""Repository for SBOMComponent entity."""

from typing import Optional

from sqlalchemy import func, delete
from sqlalchemy.orm import Session

from ..models import SBOMComponent


def _normalized_key(value: Optional[str]) -> str:
    """Normalize a string key for deduplication.

    Args:
        value: Value to normalize

    Returns:
        Lowercased, stripped string (empty string if None)
    """
    return (value or "").strip().lower()


class ComponentRepository:
    """Repository for SBOM component operations."""

    @staticmethod
    def list_components(
        db: Session, sbom_id: int, page: int = 1, page_size: int = 50
    ) -> list[SBOMComponent]:
        """List components for a specific SBOM with pagination.

        Args:
            db: Database session
            sbom_id: SBOM ID
            page: Page number (1-indexed)
            page_size: Items per page

        Returns:
            List of SBOMComponent objects
        """
        query = db.query(SBOMComponent).filter(
            SBOMComponent.sbom_id == sbom_id
        )

        offset = (page - 1) * page_size
        return query.offset(offset).limit(page_size).all()

    @staticmethod
    def upsert_components(
        db: Session, sbom_id: int, components: list[dict]
    ) -> dict:
        """Upsert components for an SBOM.

        Creates or updates components based on purl (package URL).
        Maintains two maps for deduplication: triplet and cpe.

        Args:
            db: Database session
            sbom_id: SBOM ID
            components: List of component dicts with keys:
                - name (required)
                - version (required)
                - component_type (optional, default "library")
                - purl (optional, unique identifier)
                - cpe (optional)
                - supplier (optional)
                - bom_ref (optional)

        Returns:
            Dict with keys:
            - "triplet": dict mapping "name|version|type" -> component_id
            - "cpe": dict mapping cpe -> component_id
        """
        triplet_map = {}
        cpe_map = {}

        for comp_data in components:
            name = comp_data.get("name", "").strip()
            version = comp_data.get("version", "").strip()
            component_type = comp_data.get("component_type", "library")
            purl = comp_data.get("purl", "").strip() or None
            cpe = comp_data.get("cpe", "").strip() or None
            supplier = comp_data.get("supplier", "").strip() or None
            bom_ref = comp_data.get("bom_ref", "").strip() or None

            # Build triplet key for deduplication
            triplet_key = f"{name}|{version}|{component_type}".lower()

            # Check if component already exists
            existing = None
            if purl:
                existing = (
                    db.query(SBOMComponent)
                    .filter(
                        SBOMComponent.sbom_id == sbom_id,
                        SBOMComponent.purl == purl,
                    )
                    .first()
                )

            if not existing and triplet_key in triplet_map:
                # Component already processed in this batch
                comp_id = triplet_map[triplet_key]
            elif existing:
                # Component exists in database, update it
                comp_id = existing.id
                existing.purl = purl
                existing.cpe = cpe
                existing.supplier = supplier
                existing.bom_ref = bom_ref
                db.flush()
            else:
                # Create new component
                component = SBOMComponent(
                    sbom_id=sbom_id,
                    name=name,
                    version=version,
                    component_type=component_type,
                    purl=purl,
                    cpe=cpe,
                    supplier=supplier,
                    bom_ref=bom_ref,
                )
                db.add(component)
                db.flush()
                comp_id = component.id

            # Add to triplet map
            triplet_map[triplet_key] = comp_id

            # Add to CPE map if CPE exists
            if cpe:
                cpe_normalized = _normalized_key(cpe)
                cpe_map[cpe_normalized] = comp_id

        return {
            "triplet": triplet_map,
            "cpe": cpe_map,
        }

    @staticmethod
    def count_components(db: Session, sbom_id: int) -> int:
        """Count total components for a specific SBOM.

        Args:
            db: Database session
            sbom_id: SBOM ID

        Returns:
            Total number of components
        """
        return (
            db.query(func.count(SBOMComponent.id))
            .filter(SBOMComponent.sbom_id == sbom_id)
            .scalar()
        )
