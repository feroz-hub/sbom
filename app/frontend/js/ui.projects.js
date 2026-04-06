// js/ui.projects.js

const ProjectsUI = (() => {
  // === OPTIONAL: Chart instance for Projects activity donut ===
  let projectsActivityChart = null;

  // Render "Activity (≤ 30 days) vs Stale" donut
  async function renderProjectsActivityDonut() {
    const el = document.getElementById("projectsActivityChart");
    const totalEl = document.getElementById("projectsOverviewTotal");
    if (!el) return; // Card not present, nothing to render.

    try {
      const projects = await api.get("/api/projects");
      const total = Array.isArray(projects) ? projects.length : 0;

      // Decide "active" if modified within last 30 days; else "stale".
      const DAY = 24 * 3600 * 1000;
      const now = Date.now();
      let activeRecent = 0;

      (projects || []).forEach(p => {
        const ts = Date.parse(p.modified_on || p.created_on || 0);
        if (Number.isFinite(ts) && (now - ts) <= (30 * DAY)) activeRecent++;
      });

      const stale = Math.max(0, total - activeRecent);
      if (totalEl) totalEl.textContent = `Total: ${total}`;

      // Colors (respecting your theme vibe)
      const colors = ["#0a5db4", "#64748b"]; // active recent (blue) vs stale (gray)

      if (projectsActivityChart) {
        projectsActivityChart.destroy();
        projectsActivityChart = null;
      }

      projectsActivityChart = new Chart(el.getContext("2d"), {
        type: "doughnut",
        data: {
          labels: ["Active ≤30d", "Stale"],
          datasets: [{
            data: [activeRecent, stale],
            backgroundColor: colors,
            borderColor: "#fff",
            borderWidth: 2,
            hoverOffset: 6
          }]
        },
        options: {
          plugins: { legend: { position: "bottom" } },
          cutout: "60%",
          responsive: true,
          maintainAspectRatio: false
        }
      });
    } catch (err) {
      console.error(err);
      // Non-blocking: donut just won't render if API fails
    }
  }

  function bindCreateForm() {
    $("#formCreateProject").on("submit", async (e) => {
      e.preventDefault();
      const form = e.currentTarget;

      // Clear previous errors
      clearFieldError("err_project_name");
      clearFieldError("err_project_status");
      clearFieldError("err_created_by");
      clearFieldError("err_project_details");

      const payload = {
        project_name: form.project_name.value.trim(),
        project_details: form.project_details.value.trim() || null,
        project_status: Number(form.project_status.value || 1),
        created_by: form.created_by.value.trim() || null,
      };

      // Inline validation
      let hasError = false;

      if (!payload.project_name) {
        setFieldError("err_project_name", "Project name is required.");
        hasError = true;
      }

      if (!Number.isFinite(payload.project_status) ||
          payload.project_status < 0 || payload.project_status > 1) {
        setFieldError("err_project_status", "Status must be 0 or 1.");
        hasError = true;
      }

      if (payload.created_by && !USER_ID_REGEX.test(payload.created_by)) {
        setFieldError("err_created_by", "Created By must match letters/digits/_/./- (1–64).");
        hasError = true;
      }

      if (hasError) return;

      try {
        await api.post("/api/projects", payload);
        toast("Project created", "success");
        $("#tblProjects").jtable("reload");
        if ($("#projectSelect").length) {
          await loadProjectsToSelect($("#projectSelect"));
        }
        // Refresh the activity donut after create
        renderProjectsActivityDonut().catch(()=>{});
        form.reset();
      } catch (err) {
        console.error(err);
        toast(err.message || "Failed to create project", "error");
      }
    });

    // Clear the inline error when user starts typing again
    $('input[name="project_name"]').on("input", () => clearFieldError("err_project_name"));
    $('input[name="project_status"]').on("input", () => clearFieldError("err_project_status"));
    $('input[name="created_by"]').on("input", () => clearFieldError("err_created_by"));
  }

  function initProjectsTable() {
    $("#tblProjects").jtable({
      title: "Projects",
      paging: true,
      pageSize: 5,
      gotoPageAreaVisible: false,
      sorting: true,
      defaultSorting: "id DESC",
      actions: {
        listAction: function (postData, jtParams) {
          const paging = Object.assign({}, postData, jtParams);
          return jtableWrapList(() => api.get("/api/projects"), paging);
        },
      },

      fields: {
        id: { 
          key: true,
          title: "ID",
          width: "6%",       
          display: function (data) {
            return $('<span class="masked-id" />')
              .text('—')
              .attr('data-id', data.record.id);
          }
        },
        project_name: { title: "Name" },
        project_details: { title: "Details" },
        project_status: { title: "Status", width: "8%" },
        created_by: { title: "Created By", width: "12%" },
        created_on: { title: "Created On", width: "14%" },
        modified_on: { title: "Modified On", width: "14%" },
        edit_action: {
          title: "Edit",
          sorting: false,
          width: "8%",
          display: function (data) {
            const rec = data.record;
            const projectId = rec.id;
            const $btn = $('<button type="button" class="mini-btn">Edit</button>');
            $btn.on("click", function () {
              // Prefill dialog
              $("#editProjectId").val(projectId);
              $("#editProjectName").val(rec.project_name || "");
              $("#editProjectDetails").val(rec.project_details || "");
              $("#editProjectStatus").val(
                typeof rec.project_status === "number" ? rec.project_status : ""
              );
              $("#editProjectModifiedBy").val(rec.modified_by || "");

              // Open dialog
              $("#dialogEditProject").dialog({
                modal: true,
                width: 520,
                buttons: [
                  {
                    text: "Cancel",
                    class: "btn-secondary",
                    click: function () { $(this).dialog("close"); }
                  },
                  {
                    text: "Save",
                    class: "btn-primary",
                    click: async function () {
                      const id = Number($("#editProjectId").val());
                      const name = $("#editProjectName").val().trim();
                      const details = $("#editProjectDetails").val().trim();
                      const statusRaw = $("#editProjectStatus").val().trim();
                      const modifiedBy = $("#editProjectModifiedBy").val().trim();

                      if (!modifiedBy) {
                        toast("Modified By is required", "error");
                        return;
                      }

                      // Build minimal payload: include only provided/changed fields
                      const payload = {};
                      if (name) payload.project_name = name;
                      if (details) payload.project_details = details;
                      if (statusRaw !== "") {
                        const sv = Number(statusRaw);
                        if (Number.isNaN(sv) || sv < 0 || sv > 1) {
                          toast("Status must be 0 or 1", "error");
                          return;
                        }
                        payload.project_status = sv;
                      }
                      payload.modified_by = modifiedBy;

                      try {
                        // Optional owner check: include user_id if you want backend to verify it
                        const userId = ($("#filterUserId").val() || "").toString().trim();
                        const qs = userId ? `?user_id=${encodeURIComponent(userId)}` : "";

                        await api.patch(`/api/projects/${encodeURIComponent(id)}${qs}`, payload);

                        $(this).dialog("close");
                        toast("Project updated", "success");
                        $("#tblProjects").jtable("reload");
                        if ($("#projectSelect").length) {
                          await ProjectsUI.loadProjectsToSelect($("#projectSelect"));
                        }
                        // Refresh donut (status or modified_on might have changed)
                        renderProjectsActivityDonut().catch(()=>{});
                      } catch (err) {
                        console.error(err);
                        const msg = (err && err.message) ? err.message : "Update failed";
                        if (msg.includes("403")) {
                          toast("Forbidden: user_id does not match Project.created_by", "error");
                        } else if (msg.includes("404")) {
                          toast("Project not found", "error");
                        } else if (msg.includes("422")) {
                          toast("Invalid data sent (422). Check fields.", "error");
                        } else {
                          toast(msg, "error");
                        }
                      }
                    }
                  }
                ]
              });
            });
            return $btn;
          }
        },
        delete_action: {
          title: "Delete",
          sorting: false,
          width: "8%",
          display: function (data) {
            const projectId = data.record.id;
            const name = data.record.project_name || `Project #${projectId}`;
            const $btn = $('<button type="button" class="mini-btn" style="color:#c0392b;">Delete</button>');

            $btn.on("click", function () {
              $("#dialogConfirmMessage").text(
                `Are you sure you want to delete project “${name}”? This action cannot be undone.`
              );
              $("#dialogConfirm").dialog({
                modal: true,
                resizable: false,
                buttons: [
                  {
                    text: "Cancel",
                    class: "btn-secondary",
                    click: function () { $(this).dialog("close"); }
                  },
                  {
                    text: "Delete",
                    class: "btn-danger",
                    click: async function () {
                      $(this).dialog("close");
                      try {
                        // REQUIRED by backend: confirm=yes
                        const qs = new URLSearchParams({ confirm: "yes" }).toString();
                        await api.delete(`/api/projects/${encodeURIComponent(projectId)}?${qs}`);
                        toast("Project deleted", "success");
                        $("#tblProjects").jtable("reload");
                        if ($("#projectSelect").length) {
                          await ProjectsUI.loadProjectsToSelect($("#projectSelect"));
                        }
                        // Refresh donut after deletion
                        renderProjectsActivityDonut().catch(()=>{});
                      } catch (err) {
                        console.error(err);
                        const msg = (err && err.message) ? err.message : "Delete failed";

                        // If backend says dependencies exist, offer cascade deletion
                        if (msg.includes("409") || /SBOMs or Analysis Runs exist/i.test(msg)) {
                          // Ask the user if we should delete SBOMs in this project and retry
                          $("#dialogConfirmMessage").text(
                            "This project still has SBOMs or Analysis Runs.\n\n" +
                            "Do you want to delete ALL SBOMs in this project now and then delete the project?"
                          );
                          $("#dialogConfirm").dialog({
                            modal: true,
                            resizable: false,
                            buttons: [
                              { text: "Cancel", class: "btn-secondary", click: function () { $(this).dialog("close"); } },
                              {
                                text: "Delete SBOMs & Project",
                                class: "btn-danger",
                                click: async function () {
                                  $(this).dialog("close");
                                  try {
                                    await deleteProjectCascade(projectId, name);
                                    // Reload after cascade success
                                    $("#tblProjects").jtable("reload");
                                    if ($("#projectSelect").length) {
                                      await ProjectsUI.loadProjectsToSelect($("#projectSelect"));
                                    }
                                    // Refresh donut after cascade deletion
                                    renderProjectsActivityDonut().catch(()=>{});
                                  } catch (cascadeErr) {
                                    console.error(cascadeErr);
                                    toast(cascadeErr.message || "Cascade delete failed", "error");
                                  }
                                }
                              }
                            ]
                          });
                        } else if (msg.includes("403")) {
                          toast("Forbidden: user_id (if supplied) does not match Project.created_by.", "error");
                        } else if (msg.includes("404")) {
                          toast("Project not found.", "error");
                        } else {
                          toast(msg, "error");
                        }
                      }
                    }
                  }
                ]
              });
            });

            return $btn;
          }
        },
      }
    }); 

    // Force a fresh list call and render the activity donut shortly after
    $("#tblProjects").jtable("reload");
    setTimeout(() => {
      $("#tblProjects").jtable("load");
      renderProjectsActivityDonut().catch(()=>{});
    }, 120);
  }

  /**
   * Deletes all SBOMs that belong to a project, then deletes the project.
   * It uses each SBOM's own created_by as user_id (required by backend for SBOM deletion).
   * Shows progress toasts. Throws if any step fails.
   */
  async function deleteProjectCascade(projectId, projectName) {
    toast(`Scanning SBOMs in project “${projectName}”...`, "info");

    // 1) Load all SBOMs (backend doesn't expose project_id filter, so we filter client-side)
    // NOTE: If your dataset is large, consider adding a backend filter: GET /api/sboms?project_id=...
    let sboms = [];
    try {
      sboms = await api.get(`/api/sboms`);
    } catch (err) {
      throw new Error(`Failed to load SBOMs list: ${err.message || err}`);
    }

    const inProject = (sboms || []).filter(s => Number(s.projectid) === Number(projectId));
    if (inProject.length === 0) {
      toast("No SBOMs found in project. Retrying project delete...", "info");
    } else {
      // 2) Delete SBOMs one-by-one with confirm=yes and the SBOM's own created_by
      for (let i = 0; i < inProject.length; i++) {
        const s = inProject[i];
        const sbomId = s.id;
        const userId = (s.created_by || "").trim();
        if (!userId) {
          // Backend requires user_id for SBOM deletion
          throw new Error(
            `SBOM #${sbomId} has no created_by; cannot delete. (Backend requires user_id to match created_by)`
          );
        }
        toast(`Deleting SBOM #${sbomId} (${i + 1}/${inProject.length})...`, "info");
        const params = new URLSearchParams({ user_id: userId, confirm: "yes" });
        try {
          await api.delete(`/api/sboms/${encodeURIComponent(sbomId)}?${params.toString()}`);
        } catch (err) {
          throw new Error(`Failed to delete SBOM #${sbomId}: ${err.message || err}`);
        }
      }
      toast(`Deleted ${inProject.length} SBOM(s) from project.`, "success");
    }

    // 3) Retry project deletion with confirm=yes
    try {
      const qs = new URLSearchParams({ confirm: "yes" }).toString();
      await api.delete(`/api/projects/${encodeURIComponent(projectId)}?${qs}`);
      toast(`Project “${projectName}” deleted`, "success");
    } catch (err) {
      throw new Error(`Failed to delete project after removing SBOMs: ${err.message || err}`);
    }
  }
 
  async function loadProjectsToSelect($select) {
    try {
      const projects = await api.get("/api/projects");
      $select.empty().append(`<option value="">-- select project --</option>`);
      projects.forEach(p => {
        $select.append(`<option value="${p.id}">${p.project_name} (#${p.id})</option>`);
      });
    } catch (err) {
      console.error(err);
      toast("Failed to load projects", "error");
    }
  }

  return {
    init() {
      bindCreateForm();
      initProjectsTable();
    },
    loadProjectsToSelect,
  };
})();
 