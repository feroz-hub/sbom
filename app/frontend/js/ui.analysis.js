// js/ui.analysis.js

const AnalysisUI = (() => {
  let activeRunId = null;
  let activeSbomId = null;
  let findingsTableReady = false;
  let componentsTableReady = false;
  let lastConsolidatedRunId = null;

  function statusBadge(status) {
    const s = String(status || "UNKNOWN").toUpperCase().replace(/[^A-Z0-9_]/g, "_");
    return `<span class="status-badge status-${s.toLowerCase()}">${s}</span>`;
  }

  function buildRunsQuery() {
    const params = new URLSearchParams();

    const projectId = $("#filterAnalysisProjectId").val().trim();
    const sbomId = $("#filterAnalysisSbomId").val().trim();
    const runStatus = $("#filterAnalysisStatus").val().trim();

    if (projectId) params.set("project_id", projectId);
    if (sbomId) params.set("sbom_id", sbomId);
    if (runStatus) params.set("run_status", runStatus);

    const query = params.toString();
    return query ? `?${query}` : "";
  }

  function setSummary(runs) {
    const list = Array.isArray(runs) ? runs : [];
    if (!list.length) {
      $("#analysisSummary").html(
        [
          `<div class="metric-card metric-neutral"><span>Runs</span><strong>0</strong></div>`,
          `<div class="metric-card metric-fail"><span>Fail</span><strong>0</strong></div>`,
          `<div class="metric-card metric-partial"><span>Partial</span><strong>0</strong></div>`,
          `<div class="metric-card metric-pass"><span>Pass</span><strong>0</strong></div>`,
          `<div class="metric-card metric-neutral"><span>Total Findings</span><strong>0</strong></div>`,
          `<div class="metric-card metric-error"><span>Errors</span><strong>0</strong></div>`,
        ].join("")
      );
      return;
    }

    const totals = {
      FAIL: 0,
      PASS: 0,
      PARTIAL: 0,
      NO_DATA: 0,
      ERROR: 0,
      findings: 0,
    };

    list.forEach((r) => {
      const status = String(r.run_status || "").toUpperCase();
      if (status in totals) totals[status] += 1;
      totals.findings += Number(r.total_findings || 0);
    });

    $("#analysisSummary").html(
      [
        `<div class="metric-card metric-neutral"><span>Runs</span><strong>${list.length}</strong></div>`,
        `<div class="metric-card metric-fail"><span>Fail</span><strong>${totals.FAIL}</strong></div>`,
        `<div class="metric-card metric-partial"><span>Partial</span><strong>${totals.PARTIAL}</strong></div>`,
        `<div class="metric-card metric-pass"><span>Pass</span><strong>${totals.PASS}</strong></div>`,
        `<div class="metric-card metric-neutral"><span>Total Findings</span><strong>${totals.findings}</strong></div>`,
        `<div class="metric-card metric-error"><span>Errors</span><strong>${totals.ERROR}</strong></div>`,
      ].join("")
    );
  }

  function initRunsTable() {
    $("#tblAnalysis").jtable({
      title: "Analysis Runs",
      paging: true,
      pageSize: 5,
      gotoPageAreaVisible: false,
      sorting: true,
      defaultSorting: "id DESC",
      actions: {
        listAction: function (postData, jtParams) {
          const paging = Object.assign({}, postData, jtParams);
          const query = buildRunsQuery();
          return jtableWrapList(
            () => api.get(`/api/runs${query}`).then((runs) => { setSummary(runs); return runs; }),
            paging
          );
        },
      },
      fields: {
        view_findings: {
          title: "Findings",
          sorting: false,
          width: "8%",
          display: function (data) {
            const $btn = $('<button type="button" class="mini-btn">Findings</button>');
            $btn.on("click", () => openFindingsDialog(data.record.id));
            return $btn;
          }
        },
        view_components: {
          title: "Components",
          sorting: false,
          width: "9%",
          display: function (data) {
            const $btn = $('<button type="button" class="mini-btn">Components</button>');
            $btn.on("click", () => openComponentsDialog(data.record.sbom_id));
            return $btn;
          }
        },
        id: { key: true, title: "Run ID", width: "6%" },
        sbom_id: { title: "SBOM ID", width: "6%" },
        project_id: { title: "Project", width: "7%" },
        run_status: {
          title: "Status",
          width: "8%",
          display: function (data) {
            return $(statusBadge(data.record.run_status));
          }
        },
        total_components: { title: "Components", width: "8%" },
        components_with_cpe: { title: "With CPE", width: "7%" },
        total_findings: { title: "Findings", width: "7%" },
        critical_count: { title: "Critical", width: "6%" },
        high_count: { title: "High", width: "6%" },
        medium_count: { title: "Medium", width: "6%" },
        low_count: { title: "Low", width: "6%" },
        query_error_count: { title: "QErr", width: "6%" },
        duration_ms: { title: "Duration ms", width: "8%" },
        completed_on: { title: "Completed On", width: "12%" },
      }
    });

    $("#tblAnalysis").jtable("load");
  }

  function initFindingsDialog() {
    if (findingsTableReady) return;

    $("#dialogFindings").dialog({
      autoOpen: false,
      width: Math.min(window.innerWidth - 40, 1200),
      modal: true,
    });

    $("#tblFindings").jtable({
      title: "Findings",
      paging: true,
      pageSize: 5,
      gotoPageAreaVisible: false,
      sorting: true,
      defaultSorting: "score DESC",
      actions: {
        listAction: function (postData, jtParams) {
          if (!activeRunId) {
            const d = new $.Deferred();
            d.resolve({ Result: "OK", Records: [], TotalRecordCount: 0 });
            return d;
          }

          const sev = $("#filterFindingsSeverity").val().trim();
          const params = new URLSearchParams();
          if (sev) params.set("severity", sev);
          const query = params.toString() ? `?${params.toString()}` : "";

          const paging = Object.assign({}, postData, jtParams);
          return jtableWrapList(() => api.get(`/api/runs/${activeRunId}/findings${query}`), paging);
        },
      },
      fields: {
        id: { key: true, title: "ID", width: "5%" },
        vuln_id: { title: "CVE", width: "12%" },
        severity: {
          title: "Severity",
          width: "8%",
          display: function (data) {
            return $(statusBadge(data.record.severity));
          }
        },
        score: { title: "Score", width: "6%" },
        component_name: { title: "Component", width: "14%" },
        component_version: { title: "Version", width: "8%" },
        cpe: { title: "CPE", width: "20%" },
        title: { title: "Title", width: "18%" },
        reference_url: {
          title: "Reference",
          width: "9%",
          sorting: false,
          display: function (data) {
            const url = data.record.reference_url;
            if (!url) return "";
            return $("<a/>", {
              target: "_blank",
              rel: "noopener",
              href: url,
              text: "Open",
            });
          }
        }
      }
    });

    $("#formFilterFindings").on("submit", function (e) {
      e.preventDefault();
      $("#tblFindings").jtable("reload");
    });

    findingsTableReady = true;
  }

  function initComponentsDialog() {
    if (componentsTableReady) return;

    $("#dialogComponents").dialog({
      autoOpen: false,
      width: Math.min(window.innerWidth - 40, 1100),
      modal: true,
    });

    $("#tblComponents").jtable({
      title: "SBOM Components",
      paging: true,
      pageSize: 5,
      gotoPageAreaVisible: false,
      sorting: true,
      defaultSorting: "name ASC",
      actions: {
        listAction: function (postData, jtParams) {
          if (!activeSbomId) {
            const d = new $.Deferred();
            d.resolve({ Result: "OK", Records: [], TotalRecordCount: 0 });
            return d;
          }
          const paging = Object.assign({}, postData, jtParams);
          return jtableWrapList(() => api.get(`/api/sboms/${activeSbomId}/components`), paging);
        },
      },
      fields: {
        id: { key: true, title: "ID", width: "6%" },
        name: { title: "Name", width: "20%" },
        version: { title: "Version", width: "10%" },
        component_type: { title: "Type", width: "10%" },
        purl: { title: "PURL", width: "24%" },
        cpe: { title: "CPE", width: "24%" },
        scope: { title: "Scope", width: "6%" },
      }
    });

    componentsTableReady = true;
  }

  function openFindingsDialog(runId) {
    activeRunId = runId;
    initFindingsDialog();
    $("#dialogFindings").dialog("option", "title", `Analysis Findings - Run #${runId}`);
    $("#dialogFindings").dialog("open");
    $("#tblFindings").jtable("load");
  }

  function openComponentsDialog(sbomId) {
    activeSbomId = sbomId;
    initComponentsDialog();
    $("#dialogComponents").dialog("option", "title", `SBOM Components - SBOM #${sbomId}`);
    $("#dialogComponents").dialog("open");
    $("#tblComponents").jtable("load");
  }

  function bindConsolidatedAndPdf() {
    const API_BASE = window.SBOM_API_BASE || "http://localhost:8000";

    $("#formConsolidatedAnalysis").on("submit", async function (e) {
      e.preventDefault();
      const sbomId = $("#consolidatedSbomId").val().trim();
      if (!sbomId) {
        toast("Enter SBOM ID", "error");
        return;
      }
      const $btn = $("#btnRunConsolidated");
      $btn.prop("disabled", true);
      $("#consolidatedResult").hide().empty();
      try {
        const payload = { sbom_id: Number(sbomId) };
        const run = await api.post("/analyze-sbom-consolidated", payload);
        lastConsolidatedRunId = run.runId;
        const summary = run.summary || {};
        const findings = summary.findings || {};
        const bySev = findings.bySeverity || {};
        $("#consolidatedResult").html(
          `<div class="metric-card metric-neutral"><span>Components</span><strong>${summary.components || 0}</strong></div>` +
          `<div class="metric-card metric-fail"><span>Total findings</span><strong>${findings.total || 0}</strong></div>` +
          `<div class="metric-card metric-fail"><span>Critical</span><strong>${bySev.CRITICAL || 0}</strong></div>` +
          `<div class="metric-card metric-partial"><span>High</span><strong>${bySev.HIGH || 0}</strong></div>` +
          `<div class="metric-card metric-pass"><span>Run ID</span><strong>${run.runId}</strong></div>`
        ).show();
        $("#btnDownloadPdf").prop("disabled", false);
        toast("Consolidated analysis complete. You can download the PDF.", "success");
      } catch (err) {
        console.error(err);
        toast(err.message || "Consolidated analysis failed", "error");
      } finally {
        $btn.prop("disabled", false);
      }
    });

    $("#btnDownloadPdf").on("click", async function () {
      if (lastConsolidatedRunId == null) {
        toast("Run consolidated analysis first", "error");
        return;
      }
      try {
        const resp = await fetch(`${API_BASE}/api/pdf-report`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Accept": "application/pdf" },
          body: JSON.stringify({
            runId: lastConsolidatedRunId,
            title: "SBOM Vulnerability Report",
            filename: "sbom_vulnerability_report.pdf",
          }),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          throw new Error(err.detail || resp.statusText);
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "sbom_vulnerability_report.pdf";
        a.click();
        URL.revokeObjectURL(url);
        toast("PDF download started", "success");
      } catch (err) {
        console.error(err);
        toast(err.message || "PDF download failed", "error");
      }
    });
  }

  function bindRunFilters() {
    $("#formFilterAnalysis").on("submit", function (e) {
      e.preventDefault();
      $("#tblAnalysis").jtable("load");
    });

    $("#btnResetAnalysis").on("click", function () {
      $("#filterAnalysisProjectId").val("");
      $("#filterAnalysisSbomId").val("");
      $("#filterAnalysisStatus").val("");
      $("#tblAnalysis").jtable("load");
    });
  }

  // ?? Export Data dropdown (PDF / JSON)
  function setupExportMenu() {
    // Toggle dropdown
    $("#btnExportMenu").on("click", function (e) {
      e.preventDefault();
      $(".dropdown-export").toggleClass("show");
    });

    // Close on outside click
    $(document).on("click", function (e) {
      if (!$(e.target).closest(".dropdown-export").length) {
        $(".dropdown-export").removeClass("show");
      }
    });

    // Export JSON
    $("#exportAnalysisJson").on("click", async function (e) {
      e.preventDefault();
      $(".dropdown-export").removeClass("show");
      const query = buildRunsQuery();

      try {
        const runs = await api.get(`/api/runs${query}`);
        const blob = new Blob([JSON.stringify(runs, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "analysis_runs.json";
        a.click();
        URL.revokeObjectURL(url);
      } catch (err) {
        console.error(err);
        toast("JSON export failed", "error");
      }
    });

    // Export PDF
    $("#exportAnalysisPdf").on("click", async function (e) {
      e.preventDefault();
      $(".dropdown-export").removeClass("show");
      const query = buildRunsQuery();

      try {
        const runs = await api.get(`/api/runs${query}`);

        if (!window.jspdf || !window.jspdf.jsPDF) {
          toast("PDF library not found. Please include jsPDF + AutoTable.", "error");
          return;
        }

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        const columns = [
          "Run ID", "SBOM ID", "Project ID", "Status",
          "Components", "Findings", "Completed On"
        ];

        const rows = runs.map((r) => [
          r.id,
          r.sbom_id,
          r.project_id,
          r.run_status,
          r.total_components,
          r.total_findings,
          r.completed_on,
        ]);

        doc.text("Analysis Runs Export", 14, 14);

        if (doc.autoTable) {
          doc.autoTable({
            head: [columns],
            body: rows,
            startY: 20,
          });
        } else if (window.jspdf && window.jspdf.autoTable) {
          window.jspdf.autoTable(doc, {
            head: [columns],
            body: rows,
            startY: 20,
          });
        } else {
          toast("AutoTable plugin not found for jsPDF.", "error");
          return;
        }

        doc.save("analysis_runs.pdf");
      } catch (err) {
        console.error(err);
        toast("PDF export failed", "error");
      }
    });
  }

  return {
    init() {
      bindRunFilters();
      bindConsolidatedAndPdf();
      initRunsTable();
      setupExportMenu();
    }
  };
})();
 