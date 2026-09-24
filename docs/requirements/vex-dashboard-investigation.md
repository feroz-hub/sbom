# VEX Dashboard & Investigation
## Final Implementation Requirements

**System:** SBOM Analyser  
**Module:** VEX Dashboard, Reconciliation & Investigation  
**Status:** Finalized for implementation  
**Priority:** Current development priority  
**Version:** 1.0

---

# 1. Objective

The SBOM Analyser shall provide a unified VEX investigation workflow capable of reconciling:

- vulnerabilities discovered by SBOM Analyser sources such as NVD, OSV and GHSA;
- VEX statements embedded in an uploaded SBOM;
- separately uploaded OpenVEX, CycloneDX VEX or CSAF VEX documents;
- vendor-discovered VEX documents;
- manual/internal VEX determinations made by authorized security analysts.

The system shall preserve the distinction between:

**Vulnerability detection**

and

**Vulnerability exploitability determination.**

A vulnerability discovered by the analyser must never be deleted merely because VEX says `NOT_AFFECTED`.

Similarly, a vulnerability appearing only in VEX must not be discarded merely because NVD, OSV or another analyser source did not detect it.

---

# 2. Current Implementation Baseline

The existing application already provides substantial VEX functionality.

The current backend supports:

- CycloneDX embedded VEX processing;
- OpenVEX import;
- CSAF VEX import;
- manually uploaded VEX;
- vendor-hosted VEX discovery;
- component mapping;
- `affected`;
- `not_affected`;
- `fixed`;
- `under_investigation`;
- `unknown`;
- manual VEX overrides;
- append-only override audit;
- VEX report generation;
- VEX CSV/ZIP export;
- VEX dashboard summary;
- component-level VEX management.

The existing documentation explicitly states that VEX must not silently suppress vulnerability records and that manual decisions remain effective over subsequent imported assertions. 

The existing database contains `VexDocument`, `VexStatement` and `VexOverrideAudit`. `VexStatement` already stores SBOM, component, vulnerability, status, justification, impact statement, action statement, fixed version, source and evidence. 

Therefore this enhancement shall **extend the current VEX architecture**, not replace it.

---

# 3. Current Gaps Identified from Source Code

## GAP-001 — Analyser-only findings have no default VEX investigation state

Currently an `AnalysisFinding` without a matching VEX statement appears as a vulnerability option but has no VEX decision.

The existing regression test explicitly verifies this behavior: a detected CVE results in an empty VEX statement list and only appears in `vulnerability_options`. 

### Required change

Every current analyser vulnerability context without an applicable VEX determination shall have an effective VEX status of:

**UNDER_INVESTIGATION**

---

## GAP-002 — Current VEX dashboard counts only VEX statements

`vex_dashboard_summary()` currently loads `VexStatement` records and computes its counters from those statements. Analyzer findings that have no VEX statement therefore do not contribute to the VEX dashboard. 

### Required change

The VEX dashboard shall operate on the reconciled union of:

**Current analyser findings + applicable imported/manual VEX**

rather than only `VexStatement`.

---

## GAP-003 — Finding/VEX matching relies too heavily on exact vulnerability identifiers

The existing component vulnerability union uses the upper-cased raw `finding.vuln_id` as its primary key. 

`AnalysisFinding` already supports aliases, but the current component-level reconciliation does not fully use them. 

Therefore:

```text
GHSA-xxxx
alias → CVE-2026-4001
```

and

```text
VEX → CVE-2026-4001
```

can potentially remain separate even though they describe the same vulnerability.

### Required change

Canonical vulnerability identity and aliases shall be used during reconciliation.

---

## GAP-004 — Imported native VEX state is normalized too early

Current CycloneDX mappings include:

```text
exploitable            → affected
in_triage              → under_investigation
false_positive         → not_affected
resolved               → fixed
resolved_with_pedigree → fixed
```



However, `VexStatement.status` stores the normalized application status rather than a dedicated first-class native/source status. 

CycloneDX itself defines states including `resolved`, `resolved_with_pedigree`, `exploitable`, `in_triage`, `false_positive` and `not_affected`.

### Required change

The original source state shall be preserved separately from the normalized status.

Example:

```text
Source Format:
CycloneDX

Source Status:
false_positive

Normalized Status:
not_affected
```

---

## GAP-005 — No reconciliation status exists

The system currently records the VEX determination but cannot explicitly say whether a vulnerability is:

```text
found by both analyser and VEX
analyser-only
VEX-only
conflicting
unmapped
requiring revalidation
```

### Required change

A separate reconciliation state shall be introduced.

---

## GAP-006 — Current imported-statement resolution can hide conflicts

`effective_vex_statements()` groups statements by tenant, SBOM, component and vulnerability and generally selects the newest imported statement unless a manual override exists. 

This is correct for maintaining an effective decision, but insufficient when two independent suppliers or VEX documents explicitly disagree.

### Required change

Conflicting assertions shall remain visible and shall produce an investigation condition rather than being silently resolved simply because one database row is newer.

---

## GAP-007 — Component matching can be ambiguous

The current matcher considers component ID, `bom-ref`, PURL, CPE, name, name/version and supplier/name/version. 

However, it returns a matching component rather than explicitly representing ambiguity.

### Required change

A VEX assertion shall not be assigned automatically when multiple components satisfy a weak identity match.

It shall become:

```text
UNRESOLVED_MAPPING
```

until resolved.

---

## GAP-008 — Investigation view may include findings from multiple runs

The existing component vulnerability function retrieves findings for the SBOM/component across analysis runs. 

The rest of the dashboard uses the latest successful run per eligible SBOM as its operational current-state convention. 

### Required change

The **current VEX investigation queue** shall use current findings from the latest successful analysis of each eligible SBOM.

Older findings remain available as history.

---

# 4. Core VEX Design Rule

The implementation shall use the following model:

```text
                  VULNERABILITY CONTEXT
                          │
           ┌──────────────┼──────────────┐
           │              │              │
           ▼              ▼              ▼
      ANALYSER        IMPORTED VEX     INTERNAL
      EVIDENCE         ASSERTIONS      DECISION
           │              │              │
           └──────────────┼──────────────┘
                          ▼
                  RECONCILIATION
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
      EFFECTIVE VEX STATUS      RECONCILIATION STATUS
```

Scanner evidence and VEX evidence shall remain independently traceable.

---

# 5. Vulnerability Context Identity

## VEX-CTX-001

A VEX investigation shall apply to one vulnerability in one component instance within one SBOM/product context.

The logical identity shall be:

```text
tenant_id
+
sbom_id
+
component_id
+
canonical_vulnerability_id
```

Project and product information shall be derived from the SBOM relationship.

### Rule

A CVE identifier alone shall never be sufficient to apply a VEX decision globally.

Example:

```text
SBOM A
OpenSSL 1.1.1
CVE-2026-4001
```

and:

```text
SBOM A
OpenSSL 3.0.8
CVE-2026-4001
```

are separate vulnerability contexts.

---

# 6. Canonical Vulnerability Identity

## VEX-CTX-002

The system shall maintain:

```text
canonical_vulnerability_id
aliases[]
```

Where a CVE is available, CVE should normally become the canonical identifier.

Example:

```text
Canonical:
CVE-2026-4001

Aliases:
GHSA-xxxx-yyyy-zzzz
OSV-XXXX
Vendor-123
```

Multiple analyser sources reporting aliases of the same vulnerability shall not create duplicate VEX investigations.

---

# 7. Canonical Effective VEX Status

## VEX-STAT-001

The application shall use the following four canonical investigation statuses:

```text
AFFECTED
NOT_AFFECTED
FIXED
UNDER_INVESTIGATION
```

These correspond to the minimum VEX status model defined by CISA.

---

# 8. Treatment of Existing `UNKNOWN`

The current code supports:

```text
unknown
```

as a VEX status. 

For the enhanced workflow:

**UNKNOWN shall not be treated as a fifth final investigation outcome.**

Instead:

```text
Imported/source status = UNKNOWN
        ↓
Effective status = UNDER_INVESTIGATION
```

The original `UNKNOWN` value shall still be preserved as source evidence.

For migration/backward compatibility, existing APIs may temporarily continue returning `unknown_count`, but new investigation metrics shall classify unresolved `unknown` cases under `UNDER_INVESTIGATION`.

---

# 9. Source-Native VEX Status

## VEX-STAT-002

Every imported VEX assertion shall preserve:

```text
source_format
source_status
normalized_status
source_author
source_document
source_timestamp
source_url
source_evidence
```

Example:

```text
Source Format:
CycloneDX

Source Status:
in_triage

Normalized Status:
UNDER_INVESTIGATION
```

This prevents loss of information when CycloneDX, OpenVEX and CSAF use different terminology.

---

# 10. Reconciliation Status

## VEX-REC-001

Every mapped vulnerability context shall have one reconciliation state.

Required reconciliation states:

```text
MATCHED

ANALYZER_ONLY

VEX_ONLY

CONFLICT_REVIEW_REQUIRED

REVALIDATION_REQUIRED

UNRESOLVED_MAPPING
```

Source availability/error shall be stored separately rather than being treated as a VEX determination.

---

# 11. Default Reconciliation Rules

## VEX-REC-002

### Scenario A — Analyser discovers vulnerability, no VEX exists

```text
Analyzer:
DETECTED

VEX:
NONE
```

Result:

```text
Effective Status:
UNDER_INVESTIGATION

Reconciliation:
ANALYZER_ONLY
```

This is the required default for every newly discovered vulnerability without an applicable VEX determination.

---

### Scenario B — Same vulnerability found by analyser and embedded VEX

Example:

```text
Analyzer:
CVE-4001 detected

Embedded VEX:
CVE-4001 → NOT_AFFECTED
```

Result:

```text
One Vulnerability Context

Analyzer:
DETECTED

VEX:
NOT_AFFECTED

Effective Status:
NOT_AFFECTED

Reconciliation:
MATCHED
```

The scanner finding remains stored.

---

### Scenario C — VEX vulnerability is not detected by analyser

Example:

```text
Embedded VEX:
CVE-4001 → NOT_AFFECTED

NVD:
Not detected

OSV:
Not detected
```

Result:

```text
Effective Status:
NOT_AFFECTED

Reconciliation:
VEX_ONLY
```

The vulnerability shall remain visible in the VEX investigation system.

It shall **not** be added to analyser finding counts.

---

### Scenario D — VEX-only AFFECTED vulnerability

```text
Embedded VEX:
CVE-4001 → AFFECTED

Analyzer:
NOT_DETECTED
```

Result:

```text
Effective Status:
AFFECTED

Reconciliation:
VEX_ONLY
```

The UI shall additionally highlight that the VEX producer considers the vulnerability applicable even though configured vulnerability sources did not independently identify it.

This condition shall be included in the review/action queue.

---

### Scenario E — Analyser + VEX AFFECTED

```text
Analyzer:
DETECTED

VEX:
AFFECTED
```

Result:

```text
Effective Status:
AFFECTED

Reconciliation:
MATCHED
```

---

### Scenario F — Analyser + VEX UNDER_INVESTIGATION

Result:

```text
Effective Status:
UNDER_INVESTIGATION

Reconciliation:
MATCHED
```

---

### Scenario G — Analyser redetects a vulnerability VEX says FIXED

Example:

```text
Analyzer:
CVE-4001 detected

Imported VEX:
FIXED
```

The application shall preserve:

```text
Source VEX Status:
FIXED
```

but shall not silently present the vulnerability as safely resolved.

Current operational state:

```text
Effective Status:
UNDER_INVESTIGATION

Reconciliation:
REVALIDATION_REQUIRED
```

The security analyst shall verify whether:

- the SBOM still contains an old component;
- the VEX refers to another release;
- the fix is incorrectly represented;
- the scanner produced a false positive;
- component/VEX mapping is incorrect.

After validation, the analyst may explicitly set the final decision.

---

### Scenario H — Conflicting VEX assertions

Example:

```text
Supplier A:
NOT_AFFECTED

Supplier B:
AFFECTED
```

Result:

```text
Effective Status:
UNDER_INVESTIGATION

Reconciliation:
CONFLICT_REVIEW_REQUIRED
```

Both source assertions shall remain accessible.

A security analyst must resolve the conflict.

---

# 12. NOT_AFFECTED Validation

## VEX-VAL-001

`NOT_AFFECTED` shall require:

```text
justification
```

or:

```text
impact_statement
```

The current backend already enforces this behavior. 

CISA also states that a `not_affected` assertion should provide justification and, when justification is absent, must provide an impact statement.

This rule shall remain mandatory.

---

# 13. FIXED Validation

## VEX-VAL-002

A manual `FIXED` determination shall require sufficient remediation evidence, such as:

```text
fixed_version
```

or:

```text
evidence/source reference
```

The existing validation shall be retained. 

---

# 14. Embedded CycloneDX VEX Detection

## VEX-ING-001

The application currently invokes embedded VEX processing whenever an imported CycloneDX document contains a `vulnerabilities` section. 

The enhancement shall distinguish:

```text
CycloneDX vulnerability disclosure data
```

from:

```text
CycloneDX VEX / impact analysis
```

A normal CycloneDX vulnerability entry shall **not automatically become a VEX assertion** merely because it appears under `vulnerabilities[]`.

Embedded VEX shall require actual VEX/impact-analysis evidence such as:

```text
analysis.state
analysis.justification
analysis.response
applicable affects/status information
```

where appropriate.

---

# 15. Component Mapping Rules

## VEX-MAP-001

Component mapping priority shall be:

```text
Exact component/bom-ref
        ↓
Normalized PURL
        ↓
CPE
        ↓
Canonical package identity + exact version
        ↓
Supplier + name + exact version
        ↓
Name + exact version
```

Name-only matching shall be considered weak.

If more than one component can satisfy a weak match:

```text
component_id = unresolved
reconciliation = UNRESOLVED_MAPPING
```

The system shall never attach the statement to an arbitrary first component.

The current implementation already retains completely unmatched VEX evidence instead of dropping it; this behavior shall remain. 

---

# 16. Version Applicability

## VEX-MAP-002

Before applying a VEX assertion to a component, version applicability shall be verified.

The system shall support:

```text
exact version
version list
version range
```

as supplied by the supported VEX format.

Example:

```text
VEX affects:
>= 1.0
< 1.4

SBOM component:
2.0
```

Result:

```text
VEX statement retained as source evidence

BUT

VEX must not become the effective determination
for component version 2.0.
```

---

# 17. Multiple Analyser Sources

## VEX-REC-003

If NVD, OSV and GHSA all identify the same canonical vulnerability for the same component:

```text
NVD
OSV
GHSA
   ↓
ONE vulnerability context
```

Analyzer evidence shall record all contributing sources.

The VEX dashboard shall not count this as three investigations.

---

# 18. Source Failure Handling

## VEX-REC-004

The application shall distinguish:

```text
NOT_DETECTED
NOT_QUERIED
SOURCE_UNAVAILABLE
SOURCE_ERROR
```

Example:

```text
NVD timeout
OSV timeout
```

shall not be displayed as:

```text
Analyzer did not detect vulnerability
```

because no valid negative determination occurred.

Source-query errors shall remain visible as analysis evidence.

---

# 19. Re-analysis Behaviour

## VEX-INV-001

Running analysis again shall update scanner evidence without resetting an existing investigation decision.

Example:

```text
Day 1:
CVE-5001 → UNDER_INVESTIGATION

Analyst:
CVE-5001 → NOT_AFFECTED
```

New analysis:

```text
CVE-5001 detected again
```

Result must remain:

```text
Effective VEX:
NOT_AFFECTED

Analyzer:
Detected again

Last Seen:
updated
```

The existing code already gives manual decisions precedence over subsequently imported VEX statements. 

That precedence shall be retained.

---

# 20. Current vs Historical Findings

## VEX-INV-002

Operational investigation shall use:

```text
latest successful analysis run
```

for each active eligible SBOM.

Previous runs shall be retained as history but shall not create duplicate current investigation rows.

Current VEX investigation counts shall therefore represent current product state rather than every vulnerability ever detected.

---

# 21. VEX Dashboard Count Model

## VEX-DASH-001

The previous requirement:

```text
VEX total must equal analyser finding total
```

shall be replaced.

That equality cannot always be true because legitimate VEX-only vulnerabilities may exist.

Two separate totals shall be maintained.

### Analysis Finding Total

```text
Analysis Finding Total
=
Current vulnerabilities detected by SBOM Analyser
```

### VEX Context Total

```text
VEX Context Total
=
Unique reconciled vulnerability contexts from:

Analyzer Findings
UNION
Mapped VEX Assertions
```

after deduplication.

---

# 22. VEX Status Reconciliation Invariant

## VEX-DASH-002

For mapped current VEX contexts:

```text
VEX Context Total
=
Affected
+
Not Affected
+
Fixed
+
Under Investigation
```

Example:

```text
Affected               15
Not Affected            30
Fixed                   10
Under Investigation     45
                       ───
VEX Context Total      100
```

Unresolved component mappings shall be shown separately and shall not falsely inflate component-level disposition counts.

---

# 23. VEX Coverage / Reconciliation Metrics

## VEX-DASH-003

The dashboard shall display at minimum:

```text
Total VEX Contexts

Affected

Not Affected

Fixed

Under Investigation

Analyzer Only

VEX Only

Matched

Needs Review

Unresolved Mapping
```

`Needs Review` shall include at minimum:

```text
CONFLICT_REVIEW_REQUIRED
REVALIDATION_REQUIRED
```

The UI may additionally expose these individually.

---

# 24. Example Dashboard Scenario

Input SBOM:

```text
Embedded VEX:
CVE-4001 → NOT_AFFECTED
```

Analysis:

```text
CVE-5001
CVE-5002
CVE-5003
```

No analyser source finds CVE-4001.

Expected result:

```text
Analysis Findings
────────────────────────
Total                        3


VEX Investigation
────────────────────────
Total Contexts               4

Affected                     0
Not Affected                 1
Fixed                        0
Under Investigation          3


Reconciliation
────────────────────────
Matched                      0
Analyzer Only                3
VEX Only                     1
Needs Review                 0
```

Investigation rows:

| Vulnerability | Analyzer | Imported VEX | Effective Status | Reconciliation |
|---|---|---|---|---|
| CVE-4001 | Not detected | NOT_AFFECTED | NOT_AFFECTED | VEX_ONLY |
| CVE-5001 | Detected | — | UNDER_INVESTIGATION | ANALYZER_ONLY |
| CVE-5002 | Detected | — | UNDER_INVESTIGATION | ANALYZER_ONLY |
| CVE-5003 | Detected | — | UNDER_INVESTIGATION | ANALYZER_ONLY |

---

# 25. Dashboard Scope

## VEX-DASH-004

The VEX dashboard shall use the existing hierarchy:

```text
Tenant
  ↓
Project
  ↓
Application / Product
  ↓
SBOM
```

The existing dashboard scope already limits data to:

- current tenant;
- active projects;
- active products;
- active SBOMs;
- current HEAD SBOM versions;
- selected Project/Product/SBOM hierarchy.



The same scope shall be used for VEX counts and the investigation table.

This prevents:

```text
Dashboard tile count ≠ Investigation table count
```

---

# 26. Inactive / Superseded SBOM Behaviour

## VEX-DASH-005

Inactive or superseded SBOMs shall:

- remain historically queryable where history/audit functionality permits;
- not contribute to current operational VEX dashboard counts;
- not contribute to the current investigation queue.

The existing dashboard's eligible-SBOM scoping shall remain the source of truth for this behaviour. 

---

# 27. Dedicated VEX Investigation Queue

## VEX-UI-001

A dedicated portfolio-level VEX Investigation view shall be introduced.

The existing UI is currently component-first through `ComponentVexManager`, which already provides vulnerability status, source and history for one component. 

The new page shall provide cross-SBOM investigation management.

Required table information:

```text
Vulnerability ID
Aliases
Severity
Component
Component Version
Project
Application/Product
SBOM
Analyzer Detection
Analyzer Sources
Imported VEX Source
Native VEX Status
Effective VEX Status
Reconciliation Status
Justification
Reviewer/Owner
Last Updated
Action
```

---

# 28. Investigation Filters

## VEX-UI-002

The investigation table shall support:

```text
Project
Application / Product
SBOM
Effective VEX Status
Reconciliation Status
Severity
Component
Vulnerability ID / alias search
VEX source
Analyzer source
Needs Review
```

Pagination, sorting and filtering shall occur server-side for large datasets.

---

# 29. Investigation Detail

## VEX-UI-003

Opening an investigation shall display separate evidence sections.

### Vulnerability

```text
Canonical vulnerability ID
Aliases
Severity
CVSS
Description
References
```

### Component

```text
Name
Version
PURL
CPE
bom-ref
Supplier
```

### Analyzer Evidence

```text
Detected / not detected / unavailable
Sources
Analysis run
Match strategy
Match confidence
Matched version/range
First seen
Last seen
```

### Imported VEX

```text
Source format
Source-native status
Normalized status
Author
Document
Timestamp
Justification
Impact statement
Action statement
Mitigation
Fixed version
Evidence URL
Mapping confidence
```

### Internal Investigation

```text
Effective status
Reviewer
Reason
Justification
Impact statement
Action statement
Evidence
Updated date
```

### Reconciliation

```text
MATCHED
ANALYZER_ONLY
VEX_ONLY
CONFLICT_REVIEW_REQUIRED
REVALIDATION_REQUIRED
UNRESOLVED_MAPPING
```

### History

All imported and manual determinations shall remain viewable chronologically.

---

# 30. Investigation Workflow

## VEX-INV-003

Standard workflow:

```text
Analyzer Finding
       ↓
Applicable VEX?
   ┌───┴────┐
   │        │
  Yes       No
   │        │
   ▼        ▼
Reconcile   UNDER_INVESTIGATION
   │
   ▼
Conflict?
 ┌─┴─┐
No   Yes
│     │
│     ▼
│   UNDER_INVESTIGATION
│   + REVIEW REQUIRED
│
▼
Effective VEX Status
```

Analyst resolution:

```text
UNDER_INVESTIGATION
        ↓
Security Review
        ↓
 ┌──────┼──────┐
 ↓      ↓      ↓
Affected  Not Affected  Fixed
```

---

# 31. Internal Decision Priority

## VEX-INV-004

An explicit authorized internal/manual VEX decision shall remain effective over subsequently imported external VEX assertions until:

- the internal decision is explicitly changed;
- it is explicitly revoked;
- or a future approved workflow marks it obsolete.

New imported evidence shall still be stored and visible.

It shall not silently replace the internal determination.

This preserves the application's existing append-only manual override behavior. 

---

# 32. Imported VEX Conflict Handling

## VEX-INV-005

Imported assertions shall remain independent evidence records.

Example:

```text
Vendor VEX:
NOT_AFFECTED

Internal Vendor Feed:
AFFECTED
```

The implementation shall not use status priority such as:

```text
Affected > Fixed > Under Investigation > Not Affected
```

to silently decide the result.

The current lifecycle decision engine contains such a priority helper for VEX results. 

That mechanism shall **not be used as the final conflict-resolution policy** for independently authored VEX assertions.

Instead:

```text
CONFLICT_REVIEW_REQUIRED
```

shall be created.

---

# 33. VEX Source Document Idempotency

## VEX-ING-002

Importing the exact same VEX document repeatedly shall not continually create duplicate effective assertions.

The system shall calculate or retain a stable document identity, such as:

```text
source document identifier
document version
document hash
```

Behaviour:

```text
Exact same document
→ idempotent / already imported

New version of document
→ append new source document
→ preserve old version as history
→ reconcile new assertions
```

---

# 34. VEX Document Provenance

## VEX-ING-003

`VexDocument` shall be enhanced to retain sufficient provenance.

At minimum:

```text
source_type
format
author
source_url
source_document_id
source_document_version
source_hash
asserted_at / document timestamp
uploaded_at
uploaded_by
validation_status
```

Existing discovery evidence and provider error fields shall remain. The current model already stores source URL, discovery evidence, provider errors and upload metadata. 

---

# 35. Investigation Persistence

## VEX-DATA-001

Introduce a persistent logical **VEX Investigation / Vulnerability Context** entity instead of overloading `VexStatement`.

Recommended information:

```text
id
tenant_id
sbom_id
component_id

canonical_vulnerability_id
aliases_json

effective_status
reconciliation_status

effective_vex_statement_id

first_seen_at
last_seen_at
last_analysis_run_id

assigned_to
reviewed_by
reviewed_at

created_at
updated_at

row_version
```

`VexStatement` shall remain the assertion/evidence/history store.

`AnalysisFinding` shall remain scanner evidence.

The new context shall connect both.

Conceptually:

```text
AnalysisFinding ─────┐
                     │
VexStatement ────────┼── VexInvestigation
                     │
Manual Decision ─────┘
```

---

# 36. Source-Native Status Persistence

## VEX-DATA-002

`VexStatement` or equivalent source metadata shall additionally preserve:

```text
source_format
source_status
normalized_status
asserted_at
```

Raw original source data shall continue to remain available.

---

# 37. No Scanner Finding Fabrication

## VEX-DATA-003

A VEX-only vulnerability shall **not result in an artificial `AnalysisFinding` record**.

Example:

```text
Embedded VEX:
CVE-4001

NVD/OSV:
No finding
```

Storage shall remain:

```text
VEX assertion
+
VEX investigation context
```

not:

```text
Fake AnalysisFinding
```

This maintains accurate scanner metrics.

---

# 38. No VEX Finding Suppression

## VEX-DATA-004

If an analyser finding is:

```text
NOT_AFFECTED
```

or:

```text
FIXED
```

the `AnalysisFinding` shall remain.

VEX only changes contextual disposition and prioritization.

It shall never silently delete the vulnerability evidence.

This is already an explicit principle in the existing VEX implementation and shall remain unchanged. 

---

# 39. Severity Independence

## VEX-DATA-005

VEX shall not rewrite vulnerability severity.

Example:

```text
Severity:
CRITICAL

VEX:
NOT_AFFECTED
```

shall remain:

```text
Severity:
CRITICAL

Effective VEX:
NOT_AFFECTED
```

Severity describes the vulnerability.

VEX describes product-context exploitability.

---

# 40. Audit Requirements

## VEX-AUD-001

All internal VEX decision changes shall be append-only and auditable.

Audit data shall include:

```text
Tenant
SBOM
Component
Vulnerability
Previous status
New status
Reason
Evidence
Changed by
Changed at
```

The existing `VexOverrideAudit` shall continue to be used or extended. 

---

# 41. Concurrency

## VEX-AUD-002

Two analysts editing the same vulnerability investigation must not silently overwrite each other's decisions.

Updates shall use optimistic concurrency or equivalent version checking.

Example:

```text
Analyst A opens version 5

Analyst B saves version 6

Analyst A attempts save from version 5
        ↓
Conflict response
        ↓
Reload latest decision
```

---

# 42. RBAC

## VEX-SEC-001

Existing permissions shall remain the primary authorization model.

```text
vex:read
→ view VEX dashboard/investigations/history

vex:write
→ import VEX
→ modify determination
→ resolve investigation
```

The current security routing already maps VEX reads/writes to these permissions, and SECURITY_ANALYST has VEX write capability. 

Frontend hiding/disabling controls shall not replace backend authorization.

---

# 43. Tenant Isolation

## VEX-SEC-002

Every vulnerability context, VEX statement and decision shall remain tenant-scoped.

A VEX assertion belonging to Tenant A must never match or affect a component or finding from Tenant B.

Existing tenant read/write enforcement shall remain mandatory. 

---

# 44. API Requirements

Existing APIs shall remain compatible where possible.

Existing component management APIs may continue to be used.

New portfolio-level APIs should provide the following logical capabilities:

```text
GET /api/vex/investigations

GET /api/vex/investigations/{id}

GET /dashboard/vex
```

The investigations endpoint shall support:

```text
pagination
scope filters
effective status
reconciliation status
severity
source
search
sorting
needs-review filter
```

The existing component-scoped endpoints shall continue providing focused management from the SBOM component view. 

---

# 45. `/dashboard/vex` Enhancement

## VEX-API-001

The existing response currently contains:

```text
affected_count
not_affected_count
fixed_count
under_investigation_count
unknown_count
vulnerabilities_reduced_by_vex
vulnerabilities_requiring_action
top_affected_components
```

The frontend type confirms the same shape. 

Enhance it with:

```text
total_contexts

analyzer_only_count
vex_only_count
matched_count

conflict_review_count
revalidation_required_count
unresolved_mapping_count

needs_review_count
```

`unknown_count` may remain temporarily for compatibility.

---

# 46. Existing Home Dashboard

The existing VEX summary card currently shows:

```text
Affected
Not Affected
Fixed
Investigating
Unknown
Requires Action
```



This compact card shall remain.

It shall become a summary/drill-down entry point into the dedicated VEX Investigation view rather than attempting to contain the full investigation workflow.

---

# 47. Acceptance Test Matrix

The following scenarios are mandatory before the VEX enhancement is considered complete.

| Test | Expected result |
|---|---|
| Embedded VEX CVE not found by analyser | Preserved as `VEX_ONLY` |
| Analyser CVE with no VEX | `UNDER_INVESTIGATION` + `ANALYZER_ONLY` |
| Same CVE in analyser + VEX | One context, no duplicate |
| Analyser + VEX AFFECTED | AFFECTED + MATCHED |
| Analyser + VEX NOT_AFFECTED | NOT_AFFECTED + MATCHED |
| Analyser + VEX UNDER_INVESTIGATION | UNDER_INVESTIGATION + MATCHED |
| Analyser redetects FIXED CVE | UNDER_INVESTIGATION + REVALIDATION_REQUIRED |
| VEX-only AFFECTED | AFFECTED + VEX_ONLY |
| VEX-only NOT_AFFECTED | NOT_AFFECTED + VEX_ONLY |
| VEX-only FIXED | FIXED + VEX_ONLY |
| GHSA finding aliases VEX CVE | Same context |
| Same CVE on two components | Two separate contexts |
| Same CVE on two component versions | Separate contexts |
| Multiple scanners find same vulnerability | One context, multiple evidence sources |
| Ambiguous component mapping | UNRESOLVED_MAPPING |
| VEX version range doesn't apply | VEX not applied to component |
| Conflicting VEX sources | CONFLICT_REVIEW_REQUIRED |
| Duplicate VEX document upload | Idempotent |
| Re-analysis after manual decision | Manual decision preserved |
| Source API fails | SOURCE_ERROR, not NOT_DETECTED |
| `not_affected` without evidence | Validation failure |
| Ordinary CycloneDX vulnerability with no VEX analysis | Must not automatically become VEX determination |
| CycloneDX `false_positive` | Native value preserved; normalized mapping retained |
| Inactive SBOM | Excluded from current dashboard |
| Superseded SBOM | Excluded from current dashboard |
| Cross-tenant access | Rejected |
| Concurrent analyst updates | Conflict detected |

---

# 48. Definition of Done

The VEX Dashboard & Investigation enhancement is complete when:

1. Every current analyser finding has a VEX investigation state.
2. New findings without VEX default to `UNDER_INVESTIGATION`.
3. Embedded/imported VEX-only vulnerabilities are retained.
4. Scanner findings and VEX assertions are reconciled without duplication.
5. CVE/GHSA/OSV aliases are reconciled correctly.
6. VEX status is component/version/product-context specific.
7. Source-native VEX status is preserved.
8. Conflicting assertions are visible.
9. Fixed-but-redetected vulnerabilities require revalidation.
10. Manual decisions survive re-analysis and later imports.
11. Current investigation uses latest successful analysis state.
12. Historical findings and decisions remain auditable.
13. Dashboard counts include analyser-only and VEX-only contexts correctly.
14. Dashboard status totals reconcile mathematically.
15. Unresolved mappings remain visible and cannot reduce risk.
16. Dedicated VEX Investigation UI is available.
17. Tenant/Project/Application/SBOM filters apply consistently.
18. `vex:read` and `vex:write` are enforced server-side.
19. Current exports continue to work.
20. All mandatory acceptance scenarios pass automated tests.

---

# 49. Implementation Sequence

### PR-1 — VEX Reconciliation Foundation

Implement:

```text
Vulnerability/VEX investigation context model
Canonical vulnerability identity
Source-native VEX status preservation
Reconciliation status
Document idempotency/provenance
Database migration
```

No major UI change.

---

### PR-2 — Reconciliation Engine

Implement:

```text
Latest analyser findings
+
Imported VEX assertions
+
Manual decisions
        ↓
Unified current VEX context
```

Including:

```text
Analyzer-only default → UNDER_INVESTIGATION
Alias reconciliation
VEX-only handling
Conflict detection
Fixed revalidation
Ambiguous mapping handling
```

---

### PR-3 — VEX Dashboard Metrics

Replace statement-only VEX aggregation with reconciled-context aggregation.

Implement:

```text
Total Contexts
Affected
Not Affected
Fixed
Under Investigation
Analyzer Only
VEX Only
Matched
Needs Review
Unresolved Mapping
```

All metrics must use existing dashboard scope rules.

---

### PR-4 — Portfolio Investigation API

Implement:

```text
GET investigation queue
GET investigation detail
server-side filtering
sorting
pagination
search
```

Reuse existing manual override APIs where practical.

---

### PR-5 — VEX Dashboard & Investigation UI

Implement:

```text
Dedicated VEX page
summary cards
investigation table
filters
detail drawer/page
evidence comparison
decision action
history
```

Retain the existing component-first `Manage VEX` workflow.

---

### PR-6 — Audit, Concurrency & RBAC Hardening

Implement:

```text
optimistic concurrency
assignment/reviewer
audit enhancements
authorization regression tests
tenant isolation tests
```

---

### PR-7 — Full End-to-End VEX Test Suite

Validate:

```text
Embedded VEX
OpenVEX
CycloneDX VEX
CSAF
VEX-only CVEs
Analyzer-only CVEs
Matched CVEs
Conflicts
Aliases
Version applicability
Re-analysis
Dashboard reconciliation
RBAC
Tenant isolation
Exports
```

---

# 50. Explicitly Out of Scope for This Workstream

Until the VEX workstream is completed, do not combine it with:

```text
General component inventory dashboard enhancement
SBOM active/inactive implementation changes
EOL/EOS enhancement
Upload validation redesign
Smart alternative-library recommendations
```

Existing lifecycle and dashboard functionality may be reused where required, but they are separate implementation workstreams.

---

# 51. Final Functional Model

```text
                      SBOM
                        │
              ┌─────────┴─────────┐
              │                   │
        Embedded VEX         Components
              │                   │
              │              Vulnerability
              │               Analysis
              │                   │
              ▼                   ▼
        VEX Assertions      Analyzer Findings
              │                   │
              └─────────┬─────────┘
                        │
                        ▼
             Canonical Vulnerability
                    Context
                        │
                        ▼
                  RECONCILE
                        │
       ┌────────────────┼────────────────┐
       │                │                │
    MATCHED      ANALYZER_ONLY       VEX_ONLY
       │                │                │
       │                ▼                │
       │        UNDER_INVESTIGATION      │
       │                                 │
       ├──── Conflict? ──────────────────┤
       │                                 │
       ▼                                 ▼
CONFLICT_REVIEW                 Effective Imported
   REQUIRED                       Determination
       │
       ▼
Security Analyst Review
       │
       ▼
┌───────────────┬──────────────┬───────────────┐
│               │              │               │
AFFECTED   NOT_AFFECTED      FIXED     UNDER_INVESTIGATION
```

This model shall be treated as the functional source of truth for the VEX Dashboard and Investigation implementation.