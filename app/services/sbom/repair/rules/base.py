from abc import ABC, abstractmethod

from ..diff import apply


class RepairRule(ABC):
    error_codes: set[str] = set()
    declared_spec_versions = frozenset({"1.4", "1.5", "1.6"})

    @property
    def supported_spec_versions(self):
        from app.validation.stages.detect import _SUPPORTED_CDX
        return self.declared_spec_versions.intersection(_SUPPORTED_CDX)

    def supports(self, document):
        return document.get('bomFormat') == 'CycloneDX' and document.get('specVersion') in self.supported_spec_versions

    def metadata(self):
        dimensions = {
            'duplicate_bom_ref': ['QD-02'], 'dangling_dependency_ref': ['QD-02', 'QD-03'],
            'duplicate_dependency': ['QD-03'], 'enum_normalization': ['QD-01', 'QD-04'],
            'purl_normalization': ['QD-02', 'QD-05'], 'purl_canonicalization': ['QD-02', 'QD-05'],
            'cpe_normalization': ['QD-02', 'QD-06'], 'dependency_cleanup': ['QD-03'],
        }
        return {'rule': self.name.upper(), 'display_name': self.name.replace('_', ' ').title(),
                'supported_formats': ['CYCLONEDX_JSON'], 'supported_versions': sorted(self.supported_spec_versions),
                'classification': 'AUTO_FIX', 'quality_dimensions': dimensions.get(self.name, []), 'safe': True}


    def can_repair(self, document, error) -> bool:
        return bool(self.propose(document, error))

    @abstractmethod
    def propose(self, document, error): ...

    def apply(self, document, proposal):
        return apply(document, proposal)
