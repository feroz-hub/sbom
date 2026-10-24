"""Native SPDX quality and repair safety; shared engine and existing validator."""
import copy
import json
from hashlib import sha256
from pathlib import Path

import pytest
from app.services.sbom.quality.engine import QualityEngine, comparison
from app.services.sbom.quality.policy import QualityPolicy
from app.services.sbom.repair.engine import RepairEngine
from app.services.sbom.repair.policy import RepairPolicy
from app.services.sbom.repair.registry import default_rules
from app.validation import run


def document(version='2.3'):
    doc = json.loads(Path('tests/fixtures/sboms/valid/spdx_2_3_minimal.json').read_text())
    doc['spdxVersion'] = 'SPDX-' + version
    if version == '2.2':
        doc['packages'][0]['externalRefs'][0]['referenceCategory'] = 'PACKAGE_MANAGER'
    doc['packages'][0]['downloadLocation'] = 'https://example.test/foo.tgz'
    doc['packages'][0]['checksums'] = [{'algorithm': 'SHA256', 'checksumValue': 'a' * 64}]
    return doc


def raw(doc):
    return json.dumps(doc).encode()


def score(doc):
    return QualityEngine(policy=QualityPolicy()).calculate(raw(doc))


def dimension(assessment, code):
    return next(d for d in assessment.dimensions if d.code == code)


@pytest.mark.parametrize('version', ['2.2', '2.3'])
def test_high_quality_spdx(version):
    result = score(document(version))
    assert result.supported and result.validation_status == 'PASSED'
    assert result.overall_score == 100
    assert result.engine_version == '3.0.0' and result.format == 'SPDX_JSON'
    assert result.artifact_hash == sha256(raw(document(version))).hexdigest()
    assert sum(d.weight for d in result.dimensions) == 100
    assert dimension(result, 'QD-03').name == 'Relationship Integrity'
    assert dimension(result, 'QD-08').name == 'Checksum Coverage'


def test_determinism_and_policy_bounds():
    a, b = score(document()), score(document())
    assert a.model_dump(exclude={'calculated_at'}) == b.model_dump(exclude={'calculated_at'})
    assert 0 <= a.overall_score <= 100
    with pytest.raises(ValueError):
        QualityPolicy(weights={'QD-01': 100})


@pytest.mark.parametrize('value,expected', [('NONE', 100), ('NOASSERTION', 0), ('MIT', 100)])
def test_license_sentinels_never_replaced(value, expected):
    doc = document()
    doc['packages'][0].update(licenseDeclared=value, licenseConcluded=value)
    result = score(doc)
    assert result.validation_status == 'PASSED'
    assert dimension(result, 'QD-07').score == expected
    repaired = RepairEngine().run(raw(doc))
    assert repaired.candidate == raw(doc)
    assert not any(f.repairable for f in result.findings if f.dimension == 'QD-07')


def test_valid_incomplete_quality_does_not_block_upload():
    doc = document()
    package = doc['packages'][0]
    for key in ('versionInfo', 'supplier', 'externalRefs', 'checksums'):
        package.pop(key)
    package.update(licenseDeclared='NOASSERTION', licenseConcluded='NOASSERTION')
    assert not run(raw(doc)).has_errors()
    result = score(doc)
    assert result.validation_status == 'PASSED' and result.overall_score < 80
    assert dimension(result, 'QD-05').metrics['missing'] == 1


@pytest.mark.parametrize('purpose', ['DOCUMENT', 'OTHER'])
def test_context_eligibility(purpose):
    doc = document()
    package = doc['packages'][0]
    package['primaryPackagePurpose'] = purpose
    package.pop('externalRefs')
    package.pop('checksums')
    result = score(doc)
    for code in ('QD-05', 'QD-06', 'QD-08'):
        assert dimension(result, code).metrics['eligible'] == 0
        assert dimension(result, code).score == 100


@pytest.mark.parametrize('field,code', [('externalRefs', 'QD-05'), ('checksums', 'QD-08')])
def test_invalid_values_reduce_quality(field, code):
    doc = document()
    obj = doc['packages'][0][field][0]
    obj['referenceLocator' if field == 'externalRefs' else 'checksumValue'] = 'malformed'
    assert dimension(score(doc), code).score == 0


@pytest.mark.parametrize('kind', ['DEPENDS_ON', 'DEPENDENCY_OF', 'CONTAINS', 'DESCRIBES', 'GENERATED_FROM'])
def test_duplicate_relationship_cleanup_preserves_types(kind):
    doc = document()
    rel = dict(spdxElementId='SPDXRef-DOCUMENT', relationshipType=kind, relatedSpdxElement='SPDXRef-Package-foo')
    doc['relationships'] += [rel, copy.deepcopy(rel)]
    original = raw(doc)
    result = RepairEngine().run(original)
    repaired = json.loads(result.candidate)
    assert len(repaired['relationships']) == len({json.dumps(r, sort_keys=True) for r in doc['relationships']})
    assert rel in repaired['relationships']
    assert result.report['status'] == 'REPAIRED'
    assert not run(result.candidate).has_errors()
    assert original == raw(doc)
    assert RepairEngine().run(result.candidate).candidate == result.candidate


def test_inverse_relationships_and_distinct_comments_are_retained():
    doc = document()
    doc['relationships'] += [dict(spdxElementId='SPDXRef-DOCUMENT', relationshipType='DEPENDS_ON', relatedSpdxElement='SPDXRef-Package-foo'),
                             dict(spdxElementId='SPDXRef-Package-foo', relationshipType='DEPENDENCY_OF', relatedSpdxElement='SPDXRef-DOCUMENT')]
    doc['relationships'].append({**doc['relationships'][0], 'comment': 'different evidence'})
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)


@pytest.mark.parametrize('target', ['pkg:npm/foo@1.0.0', 'foo@1.0.0', ' SPDXRef-Package-foo '])
def test_exact_unambiguous_relationship_reconstructed(target):
    doc = document()
    doc['relationships'][0]['relatedSpdxElement'] = target
    result = RepairEngine().run(raw(doc))
    assert result.report['status'] == 'REPAIRED'
    assert json.loads(result.candidate)['relationships'][0]['relatedSpdxElement'] == 'SPDXRef-Package-foo'


def test_ambiguous_reference_never_guessed():
    doc = document()
    doc['packages'].append({**copy.deepcopy(doc['packages'][0]), 'SPDXID': 'SPDXRef-other', 'supplier': 'Organization: Other'})
    doc['relationships'][0]['relatedSpdxElement'] = 'pkg:npm/foo@1.0.0'
    result = RepairEngine().run(raw(doc))
    assert result.candidate == raw(doc)
    assert result.report['validation_status'] == 'FAILED'
    assert result.report['analysis']['manual_only'] > 0


@pytest.mark.parametrize('referenced', [True, False])
def test_duplicate_id_safety(referenced):
    doc = document()
    package = {**copy.deepcopy(doc['packages'][0]), 'supplier': 'Organization: Other'}
    doc['packages'].append(package)
    if not referenced:
        doc['relationships'] = []
        root = {**copy.deepcopy(doc['packages'][0]), 'SPDXID': 'SPDXRef-root', 'name': 'root'}
        doc['packages'].append(root)
        doc['documentDescribes'] = ['SPDXRef-root']
    result = RepairEngine().run(raw(doc))
    if referenced:
        assert result.candidate == raw(doc)
        assert any(e.code == 'SBOM_VAL_E048_SPDXID_DUPLICATE' for e in run(result.candidate).errors)
    else:
        ids = [p['SPDXID'] for p in json.loads(result.candidate)['packages']]
        assert len(set(ids)) == 3
        assert RepairEngine().run(result.candidate).candidate == result.candidate


def test_external_refs_normalization_and_exact_dedup():
    doc = document()
    refs = doc['packages'][0]['externalRefs']
    refs[0]['referenceLocator'] = ' pkg:npm/foo@1.0.0?z=1&a=2 '
    refs.extend([copy.deepcopy(refs[0]), dict(referenceCategory='SECURITY', referenceType='cpe23Type', referenceLocator=' cpe:2.3:a:acme:foo:1.0.0:*:*:*:*:*:*:* ')])
    before = score(doc)
    result = RepairEngine().run(raw(doc))
    after = QualityEngine().calculate(result.candidate)
    assert result.report['status'] == 'REPAIRED'
    assert comparison(before.model_dump(mode='json'), after.model_dump(mode='json'))['improvement'] > 0
    assert dimension(before, 'QD-07').score == dimension(after, 'QD-07').score
    assert len(json.loads(result.candidate)['packages'][0]['externalRefs']) == 2
    assert RepairEngine().run(result.candidate).candidate == result.candidate


@pytest.mark.parametrize('target', ['NONE', 'NOASSERTION', 'DocumentRef-other:SPDXRef-Pkg'])
def test_legitimate_external_and_sentinel_targets_are_preserved(target):
    doc = document()
    doc['externalDocumentRefs'] = [dict(externalDocumentId='DocumentRef-other', spdxDocument='https://example.test/other', checksum=dict(algorithm='SHA1', checksumValue='a' * 40))]
    doc['relationships'].append(dict(spdxElementId='SPDXRef-Package-foo', relationshipType='DEPENDS_ON', relatedSpdxElement=target))
    assert not run(raw(doc)).has_errors()
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)
    assert dimension(score(doc), 'QD-03').score == 100


def test_undeclared_external_reference_remains_manual():
    doc = document()
    doc['relationships'][0]['relatedSpdxElement'] = 'DocumentRef-other:SPDXRef-Pkg'
    assert run(raw(doc)).has_errors()
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)


def test_checksum_representation_preserves_digest():
    doc = document()
    doc['packages'][0]['checksums'][0]['checksumValue'] = 'A' * 64
    result = RepairEngine().run(raw(doc))
    assert json.loads(result.candidate)['packages'][0]['checksums'][0]['checksumValue'] == 'a' * 64
    assert result.report['status'] == 'REPAIRED'


@pytest.mark.parametrize('suffix', [',"name":"duplicate"}', ',"bad":NaN}', ',"bad":Infinity}', '} trailing'])
def test_strict_preflight(suffix):
    value = raw(document())[:-1] + suffix.encode()
    assert run(value).has_errors()
    assert not QualityEngine().calculate(value).supported
    assert not RepairEngine().analyze(value)['repair_supported']


def test_signed_manual_and_cross_format_rule_isolation():
    doc = document()
    doc['signature'] = {'value': 'opaque'}
    assert not RepairEngine().analyze(raw(doc))['repair_supported']
    for rule in default_rules():
        if rule.name.startswith('spdx_'):
            assert not rule.supports({'bomFormat': 'CycloneDX', 'specVersion': '1.6'})
        else:
            assert not rule.supports(document())


def test_max_passes_and_partial_repair():
    doc = document()
    doc['packages'][0]['externalRefs'][0]['referenceLocator'] = ' pkg:npm/foo@1.0.0 '
    doc['dataLicense'] = 'unknown'
    result = RepairEngine(policy=RepairPolicy(max_passes=1)).run(raw(doc))
    assert result.report['passes'] <= 1
    assert result.report['status'] == 'PARTIALLY_REPAIRED'
    assert result.report['validation_status'] == 'FAILED'


@pytest.mark.parametrize('expression', ['MIT AND Apache-2.0', 'GPL-2.0-only WITH Classpath-exception-2.0'])
def test_license_expressions(expression):
    doc = document()
    doc['packages'][0].update(licenseDeclared=expression, licenseConcluded=expression)
    assert dimension(score(doc), 'QD-07').score == 100


@pytest.mark.parametrize('algorithm,length', [('SHA3-256', 64), ('BLAKE2b-256', 64), ('SHA256', 64)])
def test_checksum_algorithms_follow_supported_schema(algorithm, length):
    doc = document()
    doc['packages'][0]['checksums'] = [{'algorithm': algorithm, 'checksumValue': 'a' * length}]
    assert dimension(score(doc), 'QD-08').score == 100


def test_document_describes_exact_alias_and_ambiguous_duplicates_stay_manual():
    doc = document()
    doc['documentDescribes'] = ['pkg:npm/foo@1.0.0']
    result = RepairEngine().run(raw(doc))
    assert json.loads(result.candidate)['documentDescribes'] == ['SPDXRef-Package-foo']
    doc['packages'].append({**copy.deepcopy(doc['packages'][0]), 'supplier': 'Organization: Other'})
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)


def test_distinct_external_ref_categories_and_comments_not_collapsed():
    doc = document()
    reference = doc['packages'][0]['externalRefs'][0]
    doc['packages'][0]['externalRefs'] += [{**reference, 'comment': 'producer evidence'}, {**reference, 'referenceCategory': 'OTHER'}]
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)


def test_unknown_license_is_manual_and_invalid_stays_failed():
    doc = document()
    doc['packages'][0]['licenseDeclared'] = 'unknown-license'
    result = RepairEngine().run(raw(doc))
    assert result.candidate == raw(doc) and result.report['validation_status'] == 'FAILED'


def test_file_checksum_license_and_relationship_support():
    doc = document()
    doc['files'] = [{'SPDXID': 'SPDXRef-file', 'fileName': './main.py', 'checksums': [{'algorithm': 'SHA1', 'checksumValue': 'a' * 40}],
                     'licenseConcluded': 'MIT', 'licenseInfoInFiles': ['MIT'], 'copyrightText': 'NONE'}]
    doc['relationships'].append({'spdxElementId': 'SPDXRef-Package-foo', 'relationshipType': 'CONTAINS', 'relatedSpdxElement': 'SPDXRef-file'})
    assert not run(raw(doc)).has_errors()
    assert dimension(score(doc), 'QD-08').score == 100
    doc['files'][0]['checksums'][0]['checksumValue'] = 'a'
    assert run(raw(doc)).has_errors()
    assert dimension(score(doc), 'QD-08').score < 100


def test_unsafe_spdx_change_rolls_back_quality_candidate():
    from app.services.sbom.repair.diff import proposal
    from app.services.sbom.repair.rules.spdx import SpdxExternalReferenceRule
    from app.validation import errors as E
    class UnsafeRule(SpdxExternalReferenceRule):
        def propose(self, document, error):
            change = super().propose(document, error)
            return proposal(error['code'], change.path, change.old_value, 'invalid', self.name, 'test unsafe proposal') if change else None
    doc = document()
    doc['packages'][0]['externalRefs'][0]['referenceLocator'] = ' pkg:npm/foo@1.0.0 '
    def validator(value, **options):
        report = run(value, **options)
        if b'"invalid"' in value:
            report.add(E.E025_SCHEMA_VIOLATION, stage='schema', path='packages[0].externalRefs', message='Injected regression', remediation='Rollback')
        return report
    source = raw(doc)
    result = RepairEngine(rules=[UnsafeRule()], validator=validator).run(source)
    assert result.candidate == source and result.report['rollback']
    assert score(json.loads(result.candidate)).model_dump(exclude={'calculated_at'}) == score(doc).model_dump(exclude={'calculated_at'})


@pytest.mark.parametrize('value', ['MIT AND', '<script>instructions</script>', 'unknown-license'])
def test_malformed_license_quality_is_safe_manual(value):
    doc = document()
    doc['packages'][0]['licenseDeclared'] = value
    assessment = score(doc)
    assert dimension(assessment, 'QD-07').score < 100
    assert not any(f.repairable for f in assessment.findings if f.dimension == 'QD-07')


def test_package_purl_version_conflict_is_manual():
    doc = document()
    doc['packages'][0]['versionInfo'] = '2.0.0'
    assessment = score(doc)
    assert any(f.code == 'QUALITY_SPDX_ID_VERSION_CONFLICT' and not f.repairable for f in assessment.findings)
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)


def test_large_spdx_quality_is_indexed_and_findings_capped():
    doc = document()
    doc['packages'] = [{**copy.deepcopy(doc['packages'][0]), 'SPDXID': f'SPDXRef-Package-{i}', 'name': f'package-{i}'} for i in range(1000)]
    doc['relationships'] = [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': 'SPDXRef-Package-0'}]
    assessment = score(doc)
    assert 0 <= assessment.overall_score <= 100
    assert len(assessment.findings) <= 500
    assert dimension(assessment, 'QD-05').metrics['eligible'] == 1000
    assert all(f.repairability_assessed and not f.repairable for f in assessment.findings if f.code.endswith('DOWNLOADLOCATION_INCOMPLETE'))


def test_external_document_identifier_cannot_be_local_package_identity():
    doc = document()
    doc['packages'][0]['SPDXID'] = 'DocumentRef-not-local'
    assert any(e.code == 'SBOM_VAL_E040_SPDXID_MALFORMED' for e in run(raw(doc)).errors)
    assert RepairEngine().run(raw(doc)).candidate == raw(doc)


def test_unreferenced_duplicate_ids_with_exact_unique_external_targets():
    doc = document()
    second = {**copy.deepcopy(doc['packages'][0]), 'name': 'bar', 'supplier': 'Organization: Other',
              'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': 'pkg:npm/bar@1.0.0'}]}
    doc['packages'].append(second)
    doc['relationships'][0]['relatedSpdxElement'] = 'pkg:npm/foo@1.0.0'
    doc['relationships'].append({'spdxElementId': 'pkg:npm/foo@1.0.0', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': 'pkg:npm/bar@1.0.0'})
    result = RepairEngine().run(raw(doc))
    assert result.report['status'] == 'REPAIRED'
    candidate = json.loads(result.candidate)
    assert len({p['SPDXID'] for p in candidate['packages']}) == 2
    assert not run(result.candidate).has_errors()
    assert candidate['relationships'][1]['relationshipType'] == 'DEPENDS_ON'
    assert RepairEngine().run(result.candidate).candidate == result.candidate


def test_file_unknown_license_blocks_candidate_in_existing_validator():
    doc = document()
    doc['files'] = [{'SPDXID': 'SPDXRef-file', 'fileName': './main.py', 'checksums': [{'algorithm': 'SHA1', 'checksumValue': 'a' * 40}],
                     'licenseConcluded': 'unknown-license', 'licenseInfoInFiles': ['NOASSERTION'], 'copyrightText': 'NONE'}]
    doc['packages'][0]['externalRefs'][0]['referenceLocator'] = ' pkg:npm/foo@1.0.0 '
    result = RepairEngine().run(raw(doc))
    assert result.report['status'] == 'PARTIALLY_REPAIRED'
    assert any(e.code == 'SBOM_VAL_E043_LICENSE_EXPRESSION_INVALID' for e in run(result.candidate).errors)
    assert json.loads(result.candidate)['files'][0]['licenseConcluded'] == 'unknown-license'
