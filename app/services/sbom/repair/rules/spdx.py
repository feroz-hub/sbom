"""Restricted SPDX proposals under the shared repair engine and patch interface."""
from hashlib import sha256

from app.validation import errors as E

from ...quality.inspection import canonical_cpe, canonical_purl
from ...quality.spdx_inspection import ID_PATTERN, index_for, issue_matches, occurrences_for
from ..diff import pointer, proposal, unique_entries, value_at
from .base import RepairRule


class SpdxRule(RepairRule):
    declared_spec_versions = frozenset({'SPDX-2.2', 'SPDX-2.3'})

    @property
    def supported_spec_versions(self):
        from app.validation.stages.detect import _SUPPORTED_SPDX_JSON
        return self.declared_spec_versions.intersection(_SUPPORTED_SPDX_JSON)

    def supports(self, document):
        return document.get('spdxVersion') in self.supported_spec_versions and 'bomFormat' not in document

    def metadata(self):
        return dict(rule=self.name.upper(), rule_id=self.name.upper(), display_name=self.name.replace('_', ' ').title(),
                    supported_formats=['SPDX_JSON'], supported_versions=sorted(v.removeprefix('SPDX-') for v in self.supported_spec_versions),
                    classification='AUTO_FIX', quality_dimensions=self.dimensions, safe=True)


class SpdxIdentifierRule(SpdxRule):
    name = 'spdx_identifier'
    dimensions = ['QD-02']
    error_codes = {'QUALITY_SPDX_DUPLICATE_ID', 'QUALITY_SPDX_ID_WHITESPACE', E.E040_SPDXID_MALFORMED, E.E048_SPDXID_DUPLICATE}

    def propose(self, document, error):
        path = pointer(error['path'])
        if not path.endswith('/SPDXID') or not path.startswith(('/packages/', '/files/', '/snippets/')):
            return None
        try:
            old = value_at(document, path)
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        index = index_for(document)
        # Any occurrence outside identity declarations can imply a reference, including annotations.
        if not isinstance(old, str) or occurrences_for(document)[old] != index.refs[old]:
            return None
        new = old.strip()
        if index.refs[old] > 1 and ID_PATTERN.fullmatch(old):
            # Keep the first declaration; no mapping of ambiguous relationship endpoints is allowed.
            paths = index.identity_paths[old]
            if path == paths[0]:
                return None
            new = old + '-' + sha256(path.encode()).hexdigest()[:12]
        if not ID_PATTERN.fullmatch(new) or new == old or index.refs[new]:
            return None
        return proposal(error['code'], path, old, new, self.name, 'Normalize an unreferenced identifier only; all referenced duplicate identities remain manual.')


class SpdxReferenceRule(SpdxRule):
    name = 'spdx_reference'
    dimensions = ['QD-02', 'QD-03']
    error_codes = {'QUALITY_SPDX_DANGLING_REFERENCE', E.E072_RELATIONSHIP_ELEMENT_DANGLING, E.E025_SCHEMA_VIOLATION}

    def propose(self, document, error):
        path = pointer(error['path'])
        index = index_for(document)
        if path not in index.reference_paths:
            return None
        old = value_at(document, path)
        matches = index.matches(old)
        if len(matches) != 1 or (path.startswith("/documentDescribes/") and document.get("SPDXID") in matches):
            return None
        return proposal(error['code'], path, old, next(iter(matches)), self.name, 'Resolve an exact unambiguous existing SPDX identity; preserve relationship type and direction.')


class SpdxDeduplicationRule(SpdxRule):
    name = 'spdx_deduplication'
    dimensions = ['QD-02', 'QD-03', 'QD-08']
    error_codes = {'QUALITY_SPDX_DUPLICATE_ARRAY', E.E025_SCHEMA_VIOLATION}

    def propose(self, document, error):
        path = pointer(error['path'])
        index = index_for(document)
        if path not in index.deduplication_paths:
            return None
        try:
            old = value_at(document, path)
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        if not isinstance(old, list):
            return None
        new = unique_entries(old)
        if old == new:
            return None
        return proposal(error['code'], path, old, new, self.name, 'Retain first exact occurrence; preserve inverse relationships, comments, reference categories and package identities.')


class SpdxExternalReferenceRule(SpdxRule):
    name = 'spdx_external_reference'
    dimensions = ['QD-02', 'QD-05', 'QD-06']
    error_codes = {'QUALITY_SPDX_PURL_CANONICAL', 'QUALITY_SPDX_CPE_WHITESPACE'}

    def propose(self, document, error):
        path = pointer(error['path'])
        # Generated diagnostics select only correctly categorized PURL/CPE references.
        if not issue_matches(document, {**error, 'path': path}):
            return None
        old = value_at(document, path)
        new = (canonical_purl if error['code'].endswith('PURL_CANONICAL') else canonical_cpe)(old)
        return proposal(error['code'], path, old, new, self.name, 'Reuse semantics-preserving Phase 2 identifier normalization; supply no missing values.')


class SpdxChecksumRule(SpdxRule):
    name = 'spdx_checksum'
    dimensions = ['QD-08']
    error_codes = {'QUALITY_SPDX_CHECKSUM_FORMAT'}

    def propose(self, document, error):
        path = pointer(error['path'])
        if not issue_matches(document, {**error, 'path': path}):
            return None
        old = value_at(document, path)
        return proposal(error['code'], path, old, old.strip().lower(), self.name, 'Preserve existing digest bytes; normalize hexadecimal representation only.')
