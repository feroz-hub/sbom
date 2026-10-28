"""Release guards for quality policy, full outcomes and deterministic projections."""

import copy
import json
import subprocess
import sys

import pytest
from app.core.sbom_quality_policy import NAMES, QualityPolicy
from app.services.sbom.quality.engine import QualityEngine, comparison
from app.services.sbom.repair.engine import RepairEngine
from app.validation import errors as E
from app.validation.stages.semantic_cyclonedx import _HASH_HEX_LENGTHS

from tests.test_sbom_quality import dimension, rich_document, score


@pytest.mark.parametrize('value,grade', [(100, 'EXCELLENT'), (90, 'EXCELLENT'), (89.9, 'GOOD'),
    (80, 'GOOD'), (79.9, 'FAIR'), (70, 'FAIR'), (69.9, 'POOR'), (50, 'POOR'),
    (49.9, 'CRITICAL_QUALITY'), (0, 'CRITICAL_QUALITY')])
def test_exact_grade_boundaries(value, grade):
    assert QualityPolicy().grade(value) == grade


@pytest.mark.parametrize('case', ['zero', 'hundred', 'mixed', 'decimal'])
def test_weighted_formula_bounds_and_rounding(case):
    doc = rich_document()
    policy = QualityPolicy()
    if case == 'zero':
        doc = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'components': []}
        policy = QualityPolicy(weights={code: 100 if code == 'QD-04' else 0 for code in NAMES})
    elif case == 'mixed':
        doc['components'][0].pop('licenses')
    elif case == 'decimal':
        doc['components'].append({'type': 'library', 'name': 'beta', 'bom-ref': 'beta'})
    result = score(doc, policy=policy)
    assert sum(policy.weights.values()) == 100
    assert result.overall_score == round(sum(d.score * d.weight / 100 for d in result.dimensions), 1)
    assert 0 <= result.overall_score <= 100
    if case in {'zero', 'hundred'}:
        assert result.overall_score == (0 if case == 'zero' else 100)
    assert result.configuration == policy.model_dump(mode='json')
    assert QualityPolicy.model_validate(result.configuration).fingerprint() == result.configuration_hash


def test_assessment_is_identical_after_fresh_process_restart():
    raw = json.dumps(rich_document()).encode()
    expected = QualityEngine().calculate(raw).model_dump(mode='json', exclude={'calculated_at'})
    program = "from app.services.sbom.quality.engine import QualityEngine; import json,sys; print(json.dumps(QualityEngine().calculate(sys.stdin.buffer.read()).model_dump(mode='json', exclude={'calculated_at'})))"
    for _ in range(2):
        result = subprocess.run([sys.executable, '-c', program], input=raw, capture_output=True, check=True)
        assert json.loads(result.stdout) == expected


def test_repair_availability_is_bound_and_reproduced_without_changing_scores():
    document = rich_document()
    document['components'][0]['purl'] = ' ' + document['components'][0]['purl'] + ' '
    raw = json.dumps(document).encode()
    policy = QualityPolicy()
    enabled = QualityEngine(policy, repair_enabled=True).calculate(raw)
    disabled = QualityEngine(policy, repair_enabled=False).calculate(raw)
    assert policy.repair_enabled is True
    assert enabled.artifact_hash == disabled.artifact_hash
    assert enabled.overall_score == disabled.overall_score
    assert enabled.dimensions == disabled.dimensions
    assert enabled.configuration_hash != disabled.configuration_hash
    assert any(f.repairable for f in enabled.findings)
    assert not any(f.repairable for f in disabled.findings)
    assert disabled.configuration['repair_enabled'] is False
    reconstructed = QualityEngine(QualityPolicy.model_validate(disabled.configuration)).calculate(raw)
    assert reconstructed.model_dump(exclude={'calculated_at'}) == disabled.model_dump(exclude={'calculated_at'})


@pytest.mark.parametrize('blocking', [0, 1, 4, 150])
def test_truncated_noise_never_hides_schema_quality_or_validation_failure(blocking):
    report = E.ErrorReport()
    for i in range(E.MAX_ENTRIES + 1):
        report.add(E.E025_SCHEMA_VIOLATION, stage='schema', path=f'/noise/{i}', message='noise', remediation='n/a', severity=E.Severity.INFO)
    for i in range(blocking):
        report.add(E.E025_SCHEMA_VIOLATION, stage='schema', path=f'/blocking/{i}', message='blocking', remediation='fix')
    result = QualityEngine().calculate(json.dumps(rich_document()).encode(), report)
    assert report.truncated and result.validation_report_truncated
    assert result.validation_status == ('FAILED' if blocking else 'PASSED')
    assert dimension(result, 'QD-01').score == max(0, 100 - 25 * blocking)


@pytest.mark.parametrize('suffix', ['NaN', 'Infinity', '-Infinity'])
def test_non_json_numbers_are_never_authoritative_or_repaired(suffix):
    raw = ('{"bomFormat":"CycloneDX","specVersion":"1.6","version":'+suffix+'}').encode()
    assert not QualityEngine().calculate(raw).supported
    assert RepairEngine().run(raw).candidate == raw


@pytest.mark.parametrize('raw', [b'{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"version":2}',
    b'{"bomFormat":"CycloneDX","specVersion":"1.6","version":1} trailing', b'{"components":[[}'])
def test_ambiguous_or_malformed_json_remains_manual(raw):
    assert not QualityEngine().calculate(raw).supported
    assert RepairEngine().run(raw).candidate == raw


@pytest.mark.parametrize('algorithm,length', list(_HASH_HEX_LENGTHS.items()))
def test_current_hash_algorithms_use_actual_schema_and_lengths(algorithm, length):
    doc = rich_document()
    doc['components'][0]['hashes'] = [{'alg': algorithm, 'content': 'a' * length}]
    assert dimension(score(doc), 'QD-08').score == 100
    doc['components'][0]['hashes'][0]['content'] = 'x' * length
    assert dimension(score(doc), 'QD-08').score < 100


@pytest.mark.parametrize('version', ['1.4', '1.5', '1.6'])
def test_normalization_is_schema_compatible_across_versions(version):
    doc = rich_document(version)
    doc['components'][0]['purl'] = 'pkg:generic/%61lpha@1?b=2&a=1'
    raw = json.dumps(doc).encode()
    result = RepairEngine().run(raw)
    assert result.report['validation_status'] == 'PASSED'
    repaired = json.loads(result.candidate)
    assert repaired['specVersion'] == version
    assert repaired['components'][0]['purl'] == 'pkg:generic/alpha@1?a=1&b=2'
    assert RepairEngine().run(result.candidate).candidate == result.candidate


@pytest.mark.parametrize('loss', [0, 12.3])
def test_comparison_faithfully_exposes_no_change_or_decrease(loss):
    before = score(rich_document()).model_dump(mode='json')
    after = copy.deepcopy(before)
    after['artifact_hash'] = 'c' * 64
    after['overall_score'] -= loss
    after['dimensions'][0]['score'] -= loss
    result = comparison(before, after)
    assert result['improvement'] == -loss
    assert result['after']['artifact_hash'] == after['artifact_hash']
    assert bool(result['dimensions']) == bool(loss)
