"""SPDX 2.x projections shared by quality and deterministic rules; no conversion."""
import json
import re
from collections import Counter, defaultdict
from contextlib import contextmanager
from contextvars import ContextVar

from .inspection import canonical_cpe, canonical_purl

ID_PATTERN = re.compile(r'^SPDXRef-[a-zA-Z0-9.\-]+$')
_PREPARED = ContextVar("spdx_analysis_indexes", default=None)

EXTERNAL_PATTERN = re.compile(r'^(DocumentRef-[a-zA-Z0-9.\-]+):(SPDXRef-[a-zA-Z0-9.\-]+)$')


def records(document, key):
    values = document.get(key)
    return [(v, f'/{key}/{i}') for i, v in enumerate(values) if isinstance(v, dict)] if isinstance(values, list) else []


def external_kind(ref, version="SPDX-2.3"):
    if ref.get('referenceCategory') == ('PACKAGE_MANAGER' if version == 'SPDX-2.2' else 'PACKAGE-MANAGER') and ref.get('referenceType') == 'purl':
        return 'purl'
    if ref.get('referenceCategory') == 'SECURITY' and ref.get('referenceType') == 'cpe23Type':
        return 'cpe'
    return None


def identity(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


class SpdxIndex:
    def __init__(self, document):
        self.packages = records(document, 'packages')
        self.files = records(document, 'files')
        self.extracted_license_ids = {obj['licenseId'] for obj, _ in records(document, 'hasExtractedLicensingInfos')
                                      if isinstance(obj.get('licenseId'), str)}
        self.package_names = Counter((p.get('name'), p.get('versionInfo')) for p, _ in self.packages
                                     if isinstance(p.get('name'), str) and isinstance(p.get('versionInfo'), str))
        self.objects = [(document, '')] + self.packages + self.files + records(document, 'snippets')
        self.identity_paths = defaultdict(list)
        for obj, path in self.objects:
            if isinstance(obj.get('SPDXID'), str):
                self.identity_paths[obj['SPDXID']].append(path + '/SPDXID')
        self.refs = Counter(o['SPDXID'] for o, _ in self.objects if isinstance(o.get('SPDXID'), str))
        self.relationships = records(document, 'relationships')
        self.external_documents = Counter(r.get('externalDocumentId') for r, _ in records(document, 'externalDocumentRefs') if isinstance(r.get('externalDocumentId'), str))
        self.aliases = defaultdict(set)
        for package, _ in self.packages:
            ref = package.get('SPDXID')
            if not isinstance(ref, str) or self.refs[ref] != 1 or not ID_PATTERN.fullmatch(ref):
                continue
            for ext, _ in records(package, 'externalRefs'):
                kind = external_kind(ext, document.get("spdxVersion"))
                locator = ext.get('referenceLocator')
                if kind and isinstance(locator, str):
                    self.aliases[locator].add(ref)
                    canonical = (canonical_purl if kind == 'purl' else canonical_cpe)(locator)
                    if canonical:
                        self.aliases[canonical].add(ref)
            if isinstance(package.get('name'), str) and isinstance(package.get('versionInfo'), str):
                self.aliases[package['name'] + '@' + package['versionInfo']].add(ref)
        self.references = []
        for rel, path in self.relationships:
            for field in ('spdxElementId', 'relatedSpdxElement'):
                self.references.append((rel.get(field), f'{path}/{field}'))
        describes = document.get('documentDescribes')
        if isinstance(describes, list):
            self.references.extend((value, f'/documentDescribes/{i}') for i, value in enumerate(describes))

        self.reference_paths = {path for _, path in self.references}
        self.deduplication_paths = {'/relationships', '/documentDescribes'}
        self.deduplication_paths.update(path + '/' + key for _, path in self.packages + self.files for key in ('externalRefs', 'checksums'))

    def resolved(self, ref, allow_sentinel=False):
        if not isinstance(ref, str):
            return False
        if allow_sentinel and ref in {"NONE", "NOASSERTION"}:
            return True
        if self.refs[ref] == 1:
            return True
        match = EXTERNAL_PATTERN.fullmatch(ref)
        return bool(match and self.external_documents[match[1]] == 1)

    def matches(self, ref):
        if not isinstance(ref, str) or ref.startswith('DocumentRef-') or self.refs[ref]:
            return set()
        trimmed = ref.strip()
        if self.refs[trimmed] == 1 and ID_PATTERN.fullmatch(trimmed):
            return {trimmed}
        exact = self.aliases.get(ref, set())
        if exact:
            return exact
        for canonical in (canonical_purl(ref), canonical_cpe(ref)):
            if canonical and canonical in self.aliases:
                return self.aliases[canonical]
        return set()


@contextmanager
def prepared_spdx(document):
    """Cache read-only projections for one analysis, never across artifacts/requests.

    Proposal application is copy-on-write and happens outside this scope. Reset
    even on exceptions, so mutated documents and concurrent tenants cannot reuse
    stale identities. Independent rule calls still build fresh indexes.
    """
    token = _PREPARED.set({'document': document}) if isinstance(document, dict) and document.get('spdxVersion') else None
    try:
        yield
    finally:
        if token is not None:
            _PREPARED.reset(token)


def index_for(document):
    state = _PREPARED.get()
    if state is None or state['document'] is not document:
        return SpdxIndex(document)
    if 'index' not in state:
        state['index'] = SpdxIndex(document)
    return state['index']


def occurrences_for(document):
    state = _PREPARED.get()
    if state is not None and state['document'] is document and 'occurrences' in state:
        return state['occurrences']
    counts = Counter()
    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            counts[value] += 1
    if state is not None and state['document'] is document:
        state['occurrences'] = counts
    return counts


def repair_issues(document, index=None):
    state = _PREPARED.get()
    if state is not None and state['document'] is document:
        if 'issues' not in state:
            state['issues'] = _repair_issues(document, index)
        return state['issues']
    return _repair_issues(document, index)


def issue_matches(document, error):
    state = _PREPARED.get()
    issues = repair_issues(document)
    if state is not None and state['document'] is document:
        if 'issue_keys' not in state:
            state['issue_keys'] = {(i['path'], i['code']) for i in issues}
        return (error['path'], error['code']) in state['issue_keys']
    return any(i['path'] == error['path'] and i['code'] == error['code'] for i in issues)


def _repair_issues(document, index=None):
    index = index or index_for(document)
    issues = []
    def add(code, path, message):
        issues.append(dict(code='QUALITY_SPDX_' + code, path=path, message=message, severity='minor'))
    for obj, path in index.objects:
        ref = obj.get('SPDXID')
        if isinstance(ref, str):
            if index.refs[ref] > 1:
                add('DUPLICATE_ID', path + '/SPDXID', 'SPDXID is declared by multiple objects; referenced duplicates require manual review.')
            elif ref != ref.strip() and ID_PATTERN.fullmatch(ref.strip()):
                add('ID_WHITESPACE', path + '/SPDXID', 'SPDXID contains surrounding whitespace.')
    for ref, path in index.references:
        if not index.resolved(ref, allow_sentinel=path.endswith("/relatedSpdxElement")) or (path.startswith("/documentDescribes/") and ref == document.get("SPDXID")):
            add('DANGLING_REFERENCE', path, 'SPDX reference is unresolved or ambiguous; external references are never guessed.')
    for key in ('relationships', 'documentDescribes'):
        values = document.get(key)
        if isinstance(values, list) and len({identity(v) for v in values}) < len(values):
            add('DUPLICATE_ARRAY', '/' + key, 'Exact duplicate entries can be removed without changing relationship semantics.')
    for obj, path in index.packages + index.files:
        for key in ('externalRefs', 'checksums'):
            values = obj.get(key)
            if isinstance(values, list) and len({identity(v) for v in values}) < len(values):
                add('DUPLICATE_ARRAY', path + '/' + key, 'Only exact duplicate records, including comments and types, can be removed.')
        for ext, extpath in records(obj, 'externalRefs'):
            kind = external_kind(ext, document.get("spdxVersion"))
            old = ext.get('referenceLocator')
            canonical = (canonical_purl if kind == 'purl' else canonical_cpe)(old) if kind else None
            if canonical and canonical != old:
                add('PURL_CANONICAL' if kind == 'purl' else 'CPE_WHITESPACE', path + extpath + '/referenceLocator', 'Canonicalize only existing external-reference identity.')
        for checksum, chkpath in records(obj, 'checksums'):
            old = checksum.get('checksumValue')
            if isinstance(old, str) and re.fullmatch('[0-9a-fA-F]+', old.strip()) and old != old.strip().lower():
                add('CHECKSUM_FORMAT', path + chkpath + '/checksumValue', 'Normalize hexadecimal casing and surrounding whitespace; never calculate a checksum.')
    return issues
