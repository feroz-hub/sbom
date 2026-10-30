# SBOM Analyzer — Manual UI Test Plan

End-to-end smoke test of the SBOM Analyzer web UI using the bundled sample
files in [samples/](samples/). Follow the sections in order — later steps
depend on artefacts created earlier.

---

## 0. Sample files

Two SBOMs ship with the repo. Both contain intentionally vulnerable
components so the analyzer has something to find.

| File | Format | Components | Purpose |
|---|---|---|---|
| [samples/cyclonedx-multi-ecosystem.json](samples/cyclonedx-multi-ecosystem.json) | CycloneDX 1.6 | Java, Python, Node, Go, .NET, Rust | Multi-ecosystem coverage |
| [samples/spdx-web-app.json](samples/spdx-web-app.json) | SPDX 2.3 | log4j, jackson-databind, … | SPDX format coverage |

---

## 1. Start the stack

From the repository root, run the single local development manager:

```sh
python3 scripts/dev.py
```

No command means `start`. Keep this foreground process running while testing.
The launcher prepares project dependencies as needed, verifies or resumes the
selected profile's PostgreSQL/Redis dependencies, and manages FastAPI, Next.js,
the default Celery worker, the reports worker, and exactly one Celery Beat.
Wait for the launcher's application-ready message; a process merely running is
not sufficient. Missing system software, approved HTTPS trust, external identity
services and explicit database setup may still require operator action. See the
[setup guide](scripts/BOOTSTRAP.md) and [lifecycle guide](docs/dev-launcher-lifecycle.md).

Manage the same checkout from another terminal; do not start individual services:

```sh
python3 scripts/dev.py start
python3 scripts/dev.py stop
python3 scripts/dev.py restart
python3 scripts/dev.py status
python3 scripts/dev.py doctor
python3 scripts/dev.py logs
python3 scripts/dev.py logs --service reports --lines 80
```

`status`, `doctor` and `logs` inspect the environment. Use `restart` only when
needed. `stop` or Ctrl+C stops verified launcher-owned application processes;
database containers, persisted data, credentials and certificates are preserved.
Ordinary startup does not initialize or implicitly upgrade a database.

The **verified macOS Greenfield environment** uses:

- Frontend: **https://localhost:13000**
- API: **http://127.0.0.1:18000**

These are environment-specific URLs, not universal defaults. Use the selected
profile's reported URLs and preserved configuration on other installations.
The UI links below target this verified Greenfield frontend. Native Windows and
full Linux application acceptance remain unverified; consult the
[platform matrix](docs/engineering/dev-launcher-platform-matrix.md).

The manual UI procedures below are preserved. Read the
[expectations requiring review](#expectations-requiring-review) before treating
their older labels, IDs, timing or limits as acceptance criteria. This documentation
cleanup does not constitute a new UI test run.

---

## 2. Dashboard — [/](https://localhost:13000/)

**Expect:**
- Top stat cards render (Total SBOMs, Total Findings, Critical, etc.)
- "Recent SBOMs" table loads
- "Activity" and "Severity" charts render
- "Trend" chart renders without console errors

**Verify:** open browser DevTools → Network tab → reload. All `/dashboard/*`
calls should be `200`. No red errors in Console.

---

## 3. Projects — [/projects](https://localhost:13000/projects)

### 3.1 Create a project

1. Click **New Project** (top right).
2. Fill in:
   - **Name:** `Sample Test Project`
   - **Description:** `Manual UI smoke test`
3. Click **Create**.

**Expect:** modal closes, new row appears in the table.

### 3.2 Edit & delete (smoke)

1. Click the row's **edit** action → change description → save.
2. Confirm the description updates in place.
3. *Skip delete for now* — we will attach SBOMs to this project.

---

## 4. SBOMs — [/sboms](https://localhost:13000/sboms)

### 4.1 Upload CycloneDX sample

1. Click **Upload SBOM** (top right).
2. Click **Upload from file** → select
   [samples/cyclonedx-multi-ecosystem.json](samples/cyclonedx-multi-ecosystem.json).
3. The form should auto-fill:
   - **SBOM Name:** `cyclonedx-multi-ecosystem`
   - **SBOM Type / Format:** `CycloneDX` (auto-detected from filename)
   - **SBOM Content** textarea: populated with the file's JSON
4. Set **Project** → `Sample Test Project`.
5. (Optional) **SBOM Version:** `1.0.0`, **Created By:** your name.
6. Click **Upload SBOM**.

**Expect:**
- Modal closes immediately.
- Toast: `"cyclonedx-multi-ecosystem" uploaded successfully`.
- New row at the top of the table with status badge **ANALYSING**.
- A second toast appears as background analysis kicks off.
- Within ~30–120 s the badge transitions to **COMPLETED** with a finding
  count. (Analysis hits NVD/OSV/GitHub — duration depends on network.)

### 4.2 Upload SPDX sample

Repeat 4.1 with [samples/spdx-web-app.json](samples/spdx-web-app.json).

**Expect:** type auto-detects as `SPDX`. Same upload + analyse flow.

### 4.3 Duplicate-name guard

1. Click **Upload SBOM** again.
2. Type the name `cyclonedx-multi-ecosystem` and tab out of the field.

**Expect:** inline red error: *An SBOM named "…" already exists.*

Cancel the modal.

### 4.4 Validation

1. Open **Upload SBOM**, leave everything blank, click **Upload SBOM**.

**Expect:** "Name is required" and "SBOM content is required" inline errors.

---

## 5. SBOM detail — `/sboms/{id}`

From the SBOMs table click the **cyclonedx-multi-ecosystem** row.

**Expect:**
- Header: name, version, type, project, created date.
- **Components** tab/section lists ~6+ libraries (log4j-core, jackson-databind, etc.) with purl, version, ecosystem.
- **Risk summary** card shows severity counts (critical / high / medium / low).
- **Info** panel shows metadata pulled from `/api/sboms/{id}/info`.

Repeat for the **spdx-web-app** row.

---

## 6. Analysis runs — [/analysis](https://localhost:13000/analysis)

**Expect:**
- Table lists at least 2 runs (one per uploaded SBOM).
- Each row shows: SBOM name, started timestamp, status `COMPLETED`, finding counts by severity.

### 6.1 Run detail — `/analysis/{run_id}`

Click any run.

**Expect:**
- Summary header with severity totals.
- **Findings** table with columns: vulnerability ID (CVE/GHSA), component, version, severity, source (NVD / OSV / GHSA), CVSS, fix version (when known).
- Severity badges colour-coded.

### 6.2 Export SARIF

1. Click **Export → SARIF** (or equivalent).

**Expect:** browser downloads `…sarif.json`. Open it — should be valid SARIF
2.1.0 with a `runs[0].results` array.

### 6.3 Export CSV

1. Click **Export → CSV**.

**Expect:** downloads `…csv` with one row per finding.

---

## 7. Compare runs — [/analysis/compare](https://localhost:13000/analysis/compare)

1. Pick two run IDs from the analysis table (e.g. `1` and `2`).
2. URL form: `/analysis/compare?run_a=1&run_b=2`.

**Expect:**
- Side-by-side severity counts.
- Three lists: **Added** (in B not A), **Removed** (in A not B), **Common**.
- For two distinct SBOMs the diff should be substantial; comparing a run to
  itself should show empty Added/Removed lists.

---

## 8. Re-analyse an SBOM

1. Back on [/sboms](https://localhost:13000/sboms), open the **cyclonedx-multi-ecosystem** row.
2. Click **Re-analyse** (or **Analyze again**).

**Expect:**
- Status flips back to **ANALYSING**.
- A new run appears in [/analysis](https://localhost:13000/analysis).
- On completion the new run is selectable in the compare page.

---

## 9. PDF report

From any analysis run detail page, click **Download PDF report**.

**Expect:** PDF downloads, opens cleanly, contains:
- Cover page with SBOM name + run timestamp
- Severity summary
- Per-finding details

---

## 10. Project ↔ SBOM linkage

1. Go to [/projects](https://localhost:13000/projects).
2. Open **Sample Test Project**.

**Expect:** both uploaded SBOMs are listed under the project.

---

## 11. Cleanup (optional)

If you want to leave the DB clean for the next run:

1. [/sboms](https://localhost:13000/sboms) → delete both uploaded SBOMs (row action → Delete → confirm).
2. [/projects](https://localhost:13000/projects) → delete `Sample Test Project`.

Delete only test records created for this run and authorized for cleanup through
the UI. The former SQLite-file reset is obsolete for the PostgreSQL profiles.
Do not delete database files, containers or volumes, or expect startup to recreate
existing data/schema. Stopping the launcher is not a data reset.

---

## Pass criteria checklist

- [ ] Dashboard renders all widgets, no console errors
- [ ] Project create / edit works
- [ ] CycloneDX upload → analyse → COMPLETED with findings
- [ ] SPDX upload → analyse → COMPLETED with findings
- [ ] Duplicate-name validation fires
- [ ] Empty-form validation fires
- [ ] SBOM detail page shows components + risk summary
- [ ] Analysis runs list populated
- [ ] Run detail shows findings table
- [ ] SARIF export downloads and is valid
- [ ] CSV export downloads
- [ ] Compare page shows added/removed/common
- [ ] Re-analyse produces a new run
- [ ] PDF report downloads
- [ ] Project detail shows linked SBOMs

---

## Expectations requiring review

The UI procedures and checklist above retain their original workflow coverage;
the following expectations are outdated or need fresh UI/source validation.
Record an observed mismatch separately rather than changing the application to
match this older plan or marking an unexecuted case as passed.

- Sections 4, 6 and 8 use older `ANALYSING`/`COMPLETED` labels. Current run-status
  vocabulary is defined in [analysisRunStatusLabels.ts](frontend/src/lib/analysisRunStatusLabels.ts);
  confirm each UI surface's displayed label during the manual run.
- Section 7's numeric run-ID examples are historical. They do not establish valid
  selectors for the current public UUID contract, and same-run comparison behavior
  needs revalidation.
- Upload auto-fill/format assumptions, Project/Application selection, the
  duplicate-name guard, exact toasts, dashboard widgets, export labels and file
  names need confirmation against the current UI.
- The 30–120 second analysis estimate, expected run/component/finding counts and
  former fixed 20 MB upload limit are not verified guarantees. Providers, enabled
  features, input data and configured limits can change observed outcomes.
- The direct SQLite reset is retired; only the UI cleanup steps apply to test
  records in the selected PostgreSQL environment.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Frontend stuck on loading skeletons | API/dependency or selected-profile configuration problem | Run `python3 scripts/dev.py status` and `python3 scripts/dev.py logs --service api`; the verified Mac Greenfield health URL is `http://127.0.0.1:18000/health` |
| `ECONNREFUSED` in browser console | An essential component is unavailable | Inspect `status`, `doctor` and the named component's `logs`; correct the cause before `python3 scripts/dev.py restart` |
| CORS or HTTPS error | Selected origin, provider CA or approved certificate trust differs | Check the preserved profile settings and [HTTPS policy](docs/dev-launcher-lifecycle.md#preparation-and-https); do not disable TLS verification |
| Upload returns 409 | Upload conflicts with existing data | Inspect the response and current version/duplicate rules; do not delete unrelated records to satisfy an older expectation |
| Upload returns 413 | Input exceeds an enforced limit | Check the active limit and response; the historical 20 MB assumption needs review |
| Analysis remains in progress | Worker, broker or provider problem | Use `logs --service worker`, `logs --service reports` and `logs --service api` through `python3 scripts/dev.py`; inspect provider settings for the selected environment |
| Missing frontend dependency | Project installation is incomplete | Follow the launcher's setup diagnostic; `python3 scripts/dev.py setup --verbose` prepares dependencies without editing package manifests |
| Application port is occupied | Existing instance or unrelated listener | Inspect `status` and the launcher's ownership diagnostic; do not kill a process by name/port or silently change profiles |
