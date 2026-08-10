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

Open **two terminals**.

### Terminal A — backend

```bash
cd /Users/ferozebasha/Spectra/sbom
PORT=8001 python run.py
```

> Port `8000` is occupied by an unrelated app on this machine. Use `8001`
> until that is resolved.

Wait for: `Application startup complete.`

### Terminal B — frontend

```bash
cd /Users/ferozebasha/Spectra/sbom/frontend
NEXT_PUBLIC_API_URL=http://localhost:8001 ./node_modules/.bin/next dev -p 3000
```

> `npm run dev` is currently broken because `cross-env` is not installed.
> Either run `next` directly (above) or `npm install --save-dev cross-env`
> first.

Wait for: `✓ Ready in …ms`

Open **http://localhost:3000** in your browser.

---

## 2. Dashboard — [/](http://localhost:3000/)

**Expect:**
- Top stat cards render (Total SBOMs, Total Findings, Critical, etc.)
- "Recent SBOMs" table loads
- "Activity" and "Severity" charts render
- "Trend" chart renders without console errors

**Verify:** open browser DevTools → Network tab → reload. All `/dashboard/*`
calls should be `200`. No red errors in Console.

---

## 3. Projects — [/projects](http://localhost:3000/projects)

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

## 4. SBOMs — [/sboms](http://localhost:3000/sboms)

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

## 6. Analysis runs — [/analysis](http://localhost:3000/analysis)

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

## 7. Compare runs — [/analysis/compare](http://localhost:3000/analysis/compare)

1. Pick two run IDs from the analysis table (e.g. `1` and `2`).
2. URL form: `/analysis/compare?run_a=1&run_b=2`.

**Expect:**
- Side-by-side severity counts.
- Three lists: **Added** (in B not A), **Removed** (in A not B), **Common**.
- For two distinct SBOMs the diff should be substantial; comparing a run to
  itself should show empty Added/Removed lists.

---

## 8. Re-analyse an SBOM

1. Back on [/sboms](http://localhost:3000/sboms), open the **cyclonedx-multi-ecosystem** row.
2. Click **Re-analyse** (or **Analyze again**).

**Expect:**
- Status flips back to **ANALYSING**.
- A new run appears in [/analysis](http://localhost:3000/analysis).
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

1. Go to [/projects](http://localhost:3000/projects).
2. Open **Sample Test Project**.

**Expect:** both uploaded SBOMs are listed under the project.

---

## 11. Cleanup (optional)

If you want to leave the DB clean for the next run:

1. [/sboms](http://localhost:3000/sboms) → delete both uploaded SBOMs (row action → Delete → confirm).
2. [/projects](http://localhost:3000/projects) → delete `Sample Test Project`.

Or wipe the SQLite file directly:

```bash
rm /Users/ferozebasha/Spectra/sbom/sbom_api.db
```

(The backend will recreate the schema on next start.)

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

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Frontend stuck on loading skeletons | `NEXT_PUBLIC_API_URL` wrong / backend down | Verify `curl http://localhost:8001/health` returns `{"status":"ok"}` |
| `ECONNREFUSED` in browser console | Backend not running on `:8001` | Restart Terminal A |
| CORS error in console | Backend `CORS_ORIGINS` doesn't include `http://localhost:3000` | Check `app/settings.py` / env |
| Upload returns 409 | SBOM with that name already exists | Rename or delete the existing one |
| Upload returns 413 | File > 20 MB | Use a smaller SBOM |
| Analysis stuck on ANALYSING | NVD / OSV / GitHub API rate-limited or unreachable | Check backend logs; configure API tokens in `.env` |
| `npm run dev` → `cross-env: command not found` | Dev dep missing | `npm install --save-dev cross-env` |
| Backend on `:8000` returns wrong API (`/api/interview/*`) | Foreign app shadowing port | Use `PORT=8001` |
