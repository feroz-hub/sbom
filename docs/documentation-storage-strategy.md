# Documentation storage and retention strategy

**Proposal for owner review; no content is moved, uploaded, deleted or
reclassified by access level in this phase.** Current repository paths and
evidence bytes remain intact. Checked against e62951c2 on 28 October 2026.

The GitHub repository is public. Publication to it is a disclosure decision.
Do not add customer SBOMs, credentials, private UAT records or restricted audit
evidence merely to make a link easy to follow. This proposal creates no new
public links to individual evidence items.

## Placement and ownership

Ownership below names proposed accountable roles, not assigned people or an
already approved records policy.

| Category | Canonical home and proposed owner | Access controls | Retention | Traceability and links |
| --- | --- | --- | --- | --- |
| Maintained technical guidance: setup, architecture, configuration, testing, deployment, database and security runbooks | GitHub, maintained with the relevant source; engineering/domain owner, reviewed by DevOps/security where applicable. | Existing repository review controls; public-safe content only. Access/protection changes are outside this phase. | Keep supported workflow versions and change history; supersede explicitly rather than silently erase operational constraints. | Source commit/release, scope/profile/provider and verification date. Link from docs/README.md to one maintained entry per workflow. |
| ADRs, specifications and API contracts | GitHub; architecture/API/domain owner. | Review and change approval appropriate to the contract; no secrets or customer payloads. | Preserve accepted ADR IDs, supersession chain and contractual baselines. | Immutable commit/release links for decisions and released contracts; maintained index for current guidance. Unowned OpenAPI snapshots are not automatically canonical. |
| Essential test fixtures and schema/vendor assets | GitHub; test/domain maintainer with security/licence review. | Synthetic/sanitized content; intentional attack fixtures clearly identified. | Keep fixtures required by supported regression contracts and upstream provenance. | Expected outcome, origin/licence and hash where applicable. Exact byte duplicates can be intentional dependencies. |
| Stakeholder presentations and released DOCX/PDF publications | Controlled enterprise document storage; publication owner with records/security oversight. | Named groups, least privilege, versioned approvals and audit logs; controlled download/sharing, no anonymous access for restricted content. | Enterprise records schedule and contractual/regulatory obligations; periods require owner approval, not an invented number. | Publication ID/version, approval/status, source commit and content checksum. GitHub keeps an approved public-safe catalogue link only after storage/access review. |
| Approved audit reports and large evidence packages | Controlled evidence storage; assessment/QA owner plus records custodian. | Need-to-know groups, tamper-evident or immutable retention where required, audit trail; classify before publication. | Approved evidence/incident schedule, legal holds and contractual commitments govern disposition. | Assessment ID, exact source revision, commands/configuration metadata, manifest/hash and approval provenance; stable authenticated version link. |
| Historical migration/UAT/implementation records and superseded publications | Retained historical archive; migration/QA/domain owner and records custodian. Initially retain existing Git paths. | Preserve existing restrictions and provenance; any external archive must enforce the approved classification. | Retain until owner-approved disposition after reference, hold and recovery obligations are cleared. Historical approvals are not new execution authority. | Original path and revision, superseding entry, byte/hash/line-ending manifest and archive accession ID. Do not replace old results with new results. |

## Current in-place navigation

Historical families remain at their existing roots: docs/uat, docs/uuid-migration,
docs/engineering, audit, reports, security-reports, docs/sdd and dated root
publications. These path names are a catalogue of existing material, not
permission to share their contents or move every file in a subtree.

No individual historical report is labelled public-safe by this proposal.
Classification and owner approval are required before promoting it in a public
index or adding a release/publication link. Existing public availability does
not establish that disclosure was intended or that content is safe to amplify.

Current startup/database instructions live in the [documentation index](README.md).
Dated head numbers, test results and implementation limitations in historical
records remain their original evidence; no record is rewritten or removed here.

Some historical tooling is still an active dependency:
[scripts/greenfield_integrity.py](../scripts/greenfield_integrity.py) imports
infra/uuid-migration/staged-runner. [.gitattributes](../.gitattributes) preserves
bytes in UAT/migration evidence, and migration validators pin source hashes.
A dated name or exact duplicate does not establish safe deletion or relocation.

## Canonical link and publication rules

1. Keep one editable maintained source for a workflow. Released publications
   retain their own approved immutable version; a PDF/DOCX need not be an exact
   duplicate of the current Markdown source.
2. Use repository-relative links for maintained source guidance. Use immutable
   commit/release links when citing the code behind historical evidence.
3. Before adding an enterprise URL, identify the approved storage service,
   document owner, classification, readers and stable document/version ID.
   Do not invent a destination or publish a signed sharing token.
4. Keep the public catalogue free of restricted filenames/metadata where that
   would disclose sensitive work. Put the detailed registry in controlled
   storage when necessary.
5. Retain a source-revision/content-hash/approval mapping for each released
   publication or evidence package. A “latest” filename is not provenance.
6. On supersession, add the replacement relationship without changing immutable
   evidence. Maintain existing source URLs or approved forwarding links.

## One-time review material

Keep implementation summaries, verification logs, complete diffs and scenario
comparisons in controlled review artifacts. Only a sanitized decision summary
belongs in a public pull request. Do not add a permanent repository report for
each documentation session without a specific contractual, operational or records
requirement. Preserve the complete review material and its hashes before
excluding a newly proposed one-time document from a change set.

The maintained repository should retain the resulting guidance, decisions and
required contracts. This does not authorize deletion of already historical
reports, UAT evidence or approval records.

## Gate for any later migration or disposition

A later proposal must include owner approval, classification/retention review,
legal-hold check, incoming-link/import/hash dependencies, destination controls,
byte-integrity manifest, access verification and recoverable rollback. Perform
a pilot with authorized readers before broad relocation. Keep source and archive
links valid through the transition.

That later work must not remove active fixtures, loosen migration guards or
purge Git history as a cleanup shortcut. Enterprise-storage selection, named
owners, retention durations, document IDs/URLs and any access-control changes
remain unresolved decisions. No external service was contacted for publication.
