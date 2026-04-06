// js/ui.home.js
const HomeUI = (() => {

  let charts = {
    activity: null,
    severity: null
  };

  async function init() {
    await refresh();
  }

  async function refresh() {
    await loadStats();
    await loadRecent();
    await loadCharts();
  }

  async function loadStats() {
    try {
      const stats = await api.get("/dashboard/stats");

      $("#homeTotalProjects").text(stats.total_projects ?? "—");
      $("#homeTotalSboms").text(stats.total_sboms ?? "—");
      $("#homeTotalVulns").text(stats.total_vulnerabilities ?? "—");

    } catch (err) {
      console.error(err);
    }
  }

  async function loadRecent() {
    try {
      const list = await api.get("/dashboard/recent-sboms?limit=5");

      if (!list.length) {
        $("#homeRecentSboms").html("No recent SBOMs.");
        return;
      }

      $("#homeRecentSboms").html(
        list.map(s => `
          <div style="margin-bottom:6px;">
            📄 <b>${s.sbom_name}</b>
            <span style="color:#768293;"> — ${s.created_on}</span>
          </div>
        `).join("")
      );
    } catch (err) {
      console.error(err);
      $("#homeRecentSboms").html("Failed to load recent uploads.");
    }
  }

  async function loadCharts() {

    try {
      const a = await api.get("/dashboard/activity");

      if (charts.activity) charts.activity.destroy();

      charts.activity = new Chart(
        document.getElementById("homeProjectsActivityChart"),
        {
          type: "doughnut",
          data: {
            labels: ["Active ≤30d", "Stale"],
            datasets: [{
              data: [a.active_30d, a.stale],
              backgroundColor: ["#0a5db4", "#d0d8e4"]
            }]
          },
          options: { cutout: "60%", responsive: true }
        }
      );
    } catch (err) {
      console.error(err);
    }

    try {
      const sev = await api.get("/dashboard/severity");

      if (charts.severity) charts.severity.destroy();

      charts.severity = new Chart(
        document.getElementById("homeSeverityChart"),
        {
          type: "doughnut",
          data: {
            labels: ["Critical", "High", "Medium", "Low", "Unknown"],
            datasets: [{
              data: [sev.critical, sev.high, sev.medium, sev.low, sev.unknown],
              backgroundColor: ["#b40000", "#d94a4a", "#f0ad4e", "#0a5db4", "#999"]
            }]
          },
          options: { cutout: "60%", responsive: true }
        }
      );
    } catch (err) {
      console.error(err);
    }
  }

  return { init, refresh };
})();