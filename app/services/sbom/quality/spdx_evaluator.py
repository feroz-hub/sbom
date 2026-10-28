"""Format-specific evaluator within QualityEngine; native SPDX bytes, never conversion."""
import re
from collections import Counter
from functools import lru_cache

from app.validation.stages.schema import _build_json_validator, _ensure_json_schema
from app.validation.stages.semantic_spdx import _HASH_LENGTHS, _get_spdx_licensing
from license_expression import ExpressionError
from packageurl import PackageURL

from ..repair.classifier import classify
from ..repair.registry import default_rules
from .inspection import DocumentIndex, canonical_cpe, canonical_purl, valid_purl
from .models import QualityDimensionScore, QualityFinding, SbomQualityScore
from .policy import NAMES
from .spdx_inspection import ID_PATTERN, external_kind, identity, index_for, records, repair_issues


@lru_cache(maxsize=2)
def validators(version):
    schema = _ensure_json_schema('spdx', version)
    validator = _build_json_validator(schema, 'spdx', version)
    return {key: {name: validator.evolve(schema=field) for name, field in block.get('properties', {}).items()}
            for key, block in [('document', schema), ('packages', schema['properties']['packages']['items']),
                               ('files', schema['properties']['files']['items'])]}


def percent(good, total):
    return round(max(0, min(100, 100 * good / total)), 1) if total else 100.0


def checksum_valid(checksum):
    alg = checksum.get('algorithm')
    value = checksum.get('checksumValue')
    expected = {key.upper().replace('-', ''): length for key, length in _HASH_LENGTHS.items()}.get(alg.upper().replace('-', '')) if isinstance(alg, str) else None
    return bool(expected and isinstance(value, str) and len(value) == expected and re.fullmatch('[0-9a-fA-F]+', value))


def license_valid(value, document):
    if value in ('NONE', 'NOASSERTION'):
        return True
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = _get_spdx_licensing().parse(value, validate=False, strict=True)
        known = index_for(document).extracted_license_ids
        for key in _get_spdx_licensing().unknown_license_keys(parsed):
            if not key.startswith('LicenseRef-') or key not in known:
                return False
        return parsed is not None
    except (ExpressionError, ValueError, TypeError):
        return False


def evaluate(engine, document, report, common):
    index = index_for(document)
    field_checks = validators(common['spec_version'])
    rules = default_rules()
    repair_codes = set().union(*(rule.error_codes for rule in rules))
    signed = DocumentIndex(document).signed
    findings, counts, losses, totals = [], Counter(), Counter(), Counter()
    coverage = {key: Counter() for key in ('QD-05', 'QD-06', 'QD-07', 'QD-08')}
    cache = {}

    def finding(code, dim, path, message, severity='MINOR', impact=1, diagnostic=None):
        issue = diagnostic or dict(code=code, path=path)
        key = (issue['code'], issue['path'])
        assessable = engine.repair_enabled and not signed and issue['code'] in repair_codes
        assessed = not assessable or key in cache or len(cache) < 100
        if not assessable:
            kind, change = classify(document, issue, (), False)
        else:
            if key not in cache and assessed:
                cache[key] = classify(document, issue, rules, True)
            kind, change = cache.get(key, classify(document, issue, (), False))
        counts[dim] += 1
        losses[dim] += impact
        if len(findings) < engine.policy.max_findings:
            findings.append(QualityFinding(code=code, dimension=dim, path=path, severity=severity,
                            message=message, remediation='Review existing producer evidence; never infer unknown facts.',
                            quality_impact=impact, repairable=change is not None,
                            repair_classification=kind.value, repairability_assessed=assessed))

    schema_errors = [e for e in report.errors if e.stage in {'schema', 'ingress', 'detect'}]
    for entry in schema_errors:
        finding(entry.code, 'QD-01', entry.path, entry.message, 'BLOCKING', 25, entry.model_dump(mode='json'))
    for obj, path in index.objects:
        ref = obj.get('SPDXID')
        totals['QD-02'] += 1
        if not isinstance(ref, str) or not ID_PATTERN.fullmatch(ref):
            finding('QUALITY_SPDX_ID_INVALID', 'QD-02', path + '/SPDXID', 'SPDXID is missing or malformed.', 'BLOCKING')
    for ref, path in index.references:
        totals['QD-02'] += 1
        totals['QD-03'] += 1
        if not index.resolved(ref, allow_sentinel=path.endswith("/relatedSpdxElement")) or (path.startswith("/documentDescribes/") and ref == document.get("SPDXID")):
            finding('QUALITY_SPDX_REFERENCE_UNRESOLVED', 'QD-02', path, 'Reference does not resolve uniquely.', 'BLOCKING',
                    diagnostic=dict(code='QUALITY_SPDX_DANGLING_REFERENCE', path=path))
    seen_relationships = set()
    allowed_types = _ensure_json_schema('spdx', common['spec_version'])['properties']['relationships']['items']['properties']['relationshipType']['enum']
    for relationship, path in index.relationships:
        totals['QD-03'] += 1
        if relationship.get('relationshipType') not in allowed_types:
            finding('QUALITY_SPDX_RELATIONSHIP_TYPE_INVALID', 'QD-03', path + '/relationshipType', 'Declared relationship type is invalid.', 'BLOCKING')
        source, target = relationship.get('spdxElementId'), relationship.get('relatedSpdxElement')
        if isinstance(source, str) and source == target:
            finding('QUALITY_SPDX_SELF_RELATIONSHIP', 'QD-03', path, 'The existing application validator prohibits self-relationships; manual review preserves semantics.', 'BLOCKING')
        seen_relationships.add(identity(relationship))
    points = possible = 0
    for kind, rows in (('packages', index.packages), ('files', index.files)):
        for obj, path in rows:
            if kind == 'packages' and isinstance(obj.get('name'), str) and isinstance(obj.get('versionInfo'), str) and index.package_names[(obj['name'], obj['versionInfo'])] > 1:
                finding('QUALITY_SPDX_PACKAGE_IDENTITY_REVIEW', 'QD-04', path,
                        'Packages share name and version; distinct origins/builds are retained and never automatically merged.', 'INFORMATIONAL', impact=0)
            fields = {'SPDXID': 20, 'name' if kind == 'packages' else 'fileName': 40}
            if kind == 'packages':
                fields.update(versionInfo=15, downloadLocation=15, supplier=10)
            for name, weight in fields.items():
                possible += weight
                check = field_checks[kind].get(name)
                value = obj.get(name)
                if value and value != 'NOASSERTION' and check and check.is_valid(value):
                    points += weight
                else:
                    finding('QUALITY_SPDX_' + name.upper() + '_INCOMPLETE', 'QD-04', path + '/' + name,
                            'Useful package/file metadata is missing, invalid or unasserted.', impact=weight)
            purpose = obj.get('primaryPackagePurpose')
            package_eligible = kind == 'packages' and purpose not in {'DOCUMENT', 'OTHER'}
            external = records(obj, 'externalRefs')
            for id_kind, dim, applicable, canonical in (
                ('purl', 'QD-05', package_eligible, canonical_purl),
                ('cpe', 'QD-06', kind == 'packages' and purpose in {'APPLICATION', 'OPERATING-SYSTEM', 'FIRMWARE', 'DEVICE'}, canonical_cpe),
            ):
                refs = [(r, path + p + '/referenceLocator') for r, p in external if external_kind(r, document.get("spdxVersion")) == id_kind]
                metric = coverage[dim]
                metric['components_total'] += 1
                if not applicable and not refs:
                    metric['not_applicable'] += 1
                    continue
                metric['eligible'] += 1
                valid_refs = [r for r, _ in refs if (valid_purl(r.get('referenceLocator')) if id_kind == 'purl' else canonical(r.get('referenceLocator')) == r.get('referenceLocator') and bool(r.get('referenceLocator')))]
                status = 'valid' if refs and len(valid_refs) == len(refs) else 'invalid' if refs else 'missing'
                metric[status] += 1
                metric['duplicate_references'] += len(refs) - len({identity(r) for r, _ in refs})
                if status != 'valid':
                    finding('QUALITY_SPDX_' + id_kind.upper() + '_' + status.upper(), dim, path + '/externalRefs',
                            f'{id_kind.upper()} external reference is {status}; eligibility uses SPDX package purpose.')
                for ref, refpath in refs:
                    locator = ref.get('referenceLocator')
                    totals['QD-02'] += 1
                    if id_kind == 'purl' and canonical_purl(locator):
                        parsed_purl = PackageURL.from_string(canonical_purl(locator))
                        version = obj.get('versionInfo')
                        if version and parsed_purl.version and version != parsed_purl.version:
                            finding('QUALITY_SPDX_ID_VERSION_CONFLICT', 'QD-02', refpath,
                                    'Package versionInfo differs from its PURL version; neither value is changed.', 'MAJOR')
                    if canonical(locator) is None:
                        finding('QUALITY_SPDX_EXTERNAL_IDENTIFIER_INVALID', 'QD-02', refpath, 'External identifier is malformed.', 'MAJOR')
            metric = coverage['QD-07']
            metric['eligible'] += 1
            keys = ('licenseDeclared', 'licenseConcluded') if kind == 'packages' else ('licenseConcluded',)
            values = [obj.get(k) for k in keys]
            good = sum(license_valid(value, document) and value != 'NOASSERTION' for value in values)
            metric['license_fields_total'] += len(keys)
            metric['complete_license_fields'] += good
            metric['noassertion'] += sum(value == 'NOASSERTION' for value in values)
            metric['none'] += sum(value == 'NONE' for value in values)
            status = 'valid' if good == len(keys) else 'missing' if not any(values) else 'invalid' if any(value is not None and not license_valid(value, document) for value in values) else 'unasserted'
            metric[status] += 1
            for key, value in zip(keys, values, strict=True):
                if not license_valid(value, document) or value == 'NOASSERTION':
                    finding('QUALITY_SPDX_LICENSE_INCOMPLETE', 'QD-07', path + '/' + key,
                            'License information is missing, invalid or NOASSERTION. NONE is a valid explicit assertion; neither sentinel is rewritten.')
            for key in ('licenseInfoFromFiles', 'licenseInfoInFiles'):
                values = obj.get(key)
                if isinstance(values, list):
                    for i, value in enumerate(values):
                        metric['license_fields_total'] += 1
                        metric['complete_license_fields'] += license_valid(value, document) and value != 'NOASSERTION'
                        if not license_valid(value, document) or value == 'NOASSERTION':
                            finding('QUALITY_SPDX_LICENSE_INFO_INVALID', 'QD-07', f'{path}/{key}/{i}', 'Declared file-license information is invalid.')
            metric = coverage['QD-08']
            metric['components_total'] += 1
            hashes = records(obj, 'checksums')
            if kind == 'packages' and purpose in {'DOCUMENT', 'OTHER'} and not hashes:
                metric['not_applicable'] += 1
            else:
                metric['eligible'] += 1
                status = 'valid' if hashes and all(checksum_valid(h) for h, _ in hashes) else 'invalid' if hashes else 'missing'
                metric[status] += 1
                metric['components_with_hashes' if hashes else 'components_without_hashes'] += 1
                for checksum, chkpath in hashes:
                    alg = checksum.get('algorithm')
                    supported = isinstance(alg, str) and alg.upper().replace('-', '') in {key.upper().replace('-', '') for key in _HASH_LENGTHS}
                    metric['unsupported_algorithms'] += not supported
                    metric['invalid_hash_values'] += not checksum_valid(checksum)
                    if not checksum_valid(checksum):
                        finding('QUALITY_SPDX_CHECKSUM_INVALID', 'QD-08', path + chkpath, 'Checksum representation, length or algorithm is invalid; no digest can be invented.')
                if not hashes:
                    finding('QUALITY_SPDX_CHECKSUM_MISSING', 'QD-08', path + '/checksums', 'No checksum is supplied for this applicable package/file.')
    for issue in repair_issues(document, index):
        if issue['code'].endswith('DANGLING_REFERENCE'):
            dim = 'QD-03'
        elif issue['code'].endswith('CHECKSUM_FORMAT') or issue['path'].endswith('/checksums'):
            dim = 'QD-08'
        elif issue['path'] in {'/relationships', '/documentDescribes'}:
            dim = 'QD-03'
        else:
            dim = 'QD-02'
        totals[dim] += 1
        finding(issue['code'], dim, issue['path'], issue['message'],
                severity='BLOCKING' if issue['code'] in {'QUALITY_SPDX_DUPLICATE_ID', 'QUALITY_SPDX_DANGLING_REFERENCE'} else 'MINOR', diagnostic=issue)
    metadata_good = 0
    from ..repair.diff import pointer
    invalid_metadata = {pointer(e.path).split('/')[1] for e in report.errors if e.path}
    metadata_fields = {'spdxVersion': 10, 'dataLicense': 10, 'SPDXID': 10, 'name': 10, 'documentNamespace': 20, 'creationInfo': 30}
    for name, weight in metadata_fields.items():
        value = document.get(name)
        if value and name not in invalid_metadata and field_checks['document'][name].is_valid(value):
            metadata_good += weight
        else:
            finding('QUALITY_SPDX_METADATA_INCOMPLETE', 'QD-09', '/' + name, 'Useful SPDX document metadata is missing or invalid.', impact=weight)
    described = bool(document.get('documentDescribes')) or any(r.get('relationshipType') == 'DESCRIBES' and r.get('spdxElementId') == document.get('SPDXID') for r, _ in index.relationships)
    metadata_good += 10 if described else 0
    if not described:
        finding('QUALITY_SPDX_DESCRIBES_MISSING', 'QD-09', '/documentDescribes', 'Document/package describes intent is not declared.', impact=10)
    scores = {'QD-01': max(0, 100 - 25 * len(schema_errors)),
              'QD-02': percent(totals['QD-02'] - losses['QD-02'], totals['QD-02']),
              'QD-03': percent(totals['QD-03'] - losses['QD-03'], totals['QD-03']),
              'QD-04': percent(points, possible) if possible else 0,
              'QD-09': metadata_good}
    labels = {**NAMES, 'QD-03': 'Relationship Integrity', 'QD-04': 'Package / File Completeness', 'QD-08': 'Checksum Coverage'}
    dimensions = []
    for code, name in labels.items():
        metric = dict(coverage.get(code, {}))
        if code in coverage:
            scores[code] = percent(metric.get('complete_license_fields', 0), metric.get('license_fields_total', 0)) if code == 'QD-07' else percent(metric.get('valid', 0), metric.get('eligible', 0))
            metric['coverage_percentage'] = scores[code]
            for key in ('eligible', 'valid', 'missing', 'invalid', 'not_applicable'):
                metric.setdefault(key, 0)
        if code == 'QD-03':
            metric.update(relationships=len(index.relationships), unique_relationships=len(seen_relationships))
        dimensions.append(QualityDimensionScore(code=code, name=name, score=scores[code], weight=engine.policy.weights[code], finding_count=counts[code], metrics=metric))
    for f in findings:
        if f.dimension in {'QD-02', 'QD-03'}:
            f.quality_impact = round(100 * f.quality_impact / max(1, totals[f.dimension]), 1)
        elif f.dimension == 'QD-04':
            f.quality_impact = round(100 * f.quality_impact / max(1, possible), 1)
        elif f.dimension in coverage:
            f.quality_impact = round(100 / max(1, coverage[f.dimension]['eligible']), 1)
    overall = round(sum(d.score * d.weight / 100 for d in dimensions), 1)
    return SbomQualityScore(overall_score=overall, grade=engine.policy.grade(overall), dimensions=dimensions,
                           findings=findings, findings_truncated=sum(counts.values()) > len(findings), **common)
