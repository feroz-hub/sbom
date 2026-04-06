// js/ui.sboms.js
const SbomsUI = (() => {
// --- Inline analyzing dialog helpers (no HTML changes needed) ---
let analyzingDlg = null;

function showAnalyzingDialog(message = "Analyzing SBOM...") {
  if ($("#__analyzingDialog").length === 0) {
    $("body").append(`
      <div id="__analyzingDialog" title="Please wait" style="display:none;">
        <div style="display:flex;flex-direction:column;gap:10px;padding:6px 2px;">
          
          <div style="display:flex;gap:10px;align-items:center;">
            <div class="spinner" style="
                width:16px;height:16px;border:2px solid #d0d7e2;border-top-color:#0a5db4;
                border-radius:50%;animation:spin 0.8s linear infinite;">
            </div>
            <div id="__analyzingDialogText" style="font-weight:700;color:#16304f;"></div>
          </div>

          <div style="font-size:13px;color:#555;">
            <span id="analysisTimer">0s elapsed</span>
          </div>

          <button id="cancelAnalysisBtn" 
            style="padding:6px 10px;background:#c0392b;border:none;color:white;border-radius:4px;cursor:pointer;">
            Cancel Analysis
          </button>

        </div>
      </div>

      <style>
        @keyframes spin { to { transform: rotate(360deg); } }
      </style>
    `);
  }

  $("#__analyzingDialogText").text(message);

  if (!analyzingDlg) {
    analyzingDlg = $("#__analyzingDialog").dialog({
      modal: true,
      width: 360,
      closeOnEscape: false,
      open: function () {
        $(this).parent().find(".ui-dialog-titlebar-close").hide();
      }
    });
  } else {
    $("#__analyzingDialog").dialog("open");
  }
}

function hideAnalyzingDialog() {
  if (analyzingDlg) {
    $("#__analyzingDialog").dialog("close");
  }
}
  function inferSbomTypeIdByFilename(name, availableTypes) {
    // try simple heuristics: map to type typename if present
    name = (name || "").toLowerCase();
    const findTypeId = (match) => {
      const t = availableTypes.find(x => (x.typename || "").toLowerCase().includes(match));
      return t ? t.id : null;
    };

    if (name.endsWith(".spdx") || name.includes("spdx")) {
      return findTypeId("spdx");
    }
    if (name.endsWith(".json") || name.endsWith(".cdx") || name.includes("cyclonedx") || name.includes("cdx")) {
      return findTypeId("cyclonedx") || findTypeId("cdx") || findTypeId("json");
    }
    if (name.endsWith(".xml")) {
      return findTypeId("xml") || null;
    }
    return null;
  }

  async function loadTypesToSelect($select) {
    try {
      // FIX: plural endpoint
      const types = await api.get("/api/types");
      $select.data("typeList", types);
      $select.empty().append(`<option value="">-- auto / select --</option>`);
      types.forEach(t => {
        $select.append(`<option value="${t.id}">${t.typename} (#${t.id})</option>`);
      });
    } catch (err) {
      console.error(err);
      toast("Failed to load SBOM types", "error");
    }
  }

  function bindUploadForm() {
    $("#formUploadSBOM").on("submit", async (e) => {
      e.preventDefault();

      // Clear inline errors
      clearFieldError("err_sbom_file");
      clearFieldError("err_sbom_name");
      clearFieldError("err_project_select");
      clearFieldError("err_created_by_upload");
      clearFieldError("err_sbom_type");
      clearFieldError("err_sbom_version");
      clearFieldError("err_product_ver");

      const file = $("#sbomFile")[0].files[0];
      const sbomName = $("#sbomName").val().trim();
      const sbomVersion = $("#sbomVersion").val().trim();
      const productVer = $("#productVer").val().trim();
      const createdBy = $("#createdBy").val().trim();
      const projectId = $("#projectSelect").val();
      const sbomTypeSel = $("#sbomTypeSelect").val();
      const typeList = $("#sbomTypeSelect").data("typeList") || [];

      let hasError = false;

      if (!file) {
        setFieldError("err_sbom_file", "Please choose a file.");
        hasError = true;
      }
      if (!sbomName) {
        setFieldError("err_sbom_name", "SBOM name is required.");
        hasError = true;
      }
      // CHECK IF SBOM NAME ALREADY EXISTS
      try {
        const sboms = await api.get("/api/sboms");

        const exists = sboms.some(s =>
          (s.sbom_name || "").toLowerCase() === sbomName.toLowerCase()
        );

        if (exists) {
          setFieldError(
            "err_sbom_name",
            "SBOM name already exists. Please choose a different name."
          );
          return; // STOP upload
        }
      } catch (err) {
        console.error(err);
        toast("Unable to validate SBOM name", "error");
        return;
      }

      if (!projectId) {
        setFieldError("err_project_select", "Please select a project.");
        hasError = true;
      }
      if (createdBy && !USER_ID_REGEX.test(createdBy)) {
        setFieldError("err_created_by_upload", "Created By must match letters/digits/_/./- (1–64).");
        hasError = true;
      }

      if (hasError) return;

      const fileText = await file.text().catch(() => null);
      if (!fileText) {
        setFieldError("err_sbom_file", "Unable to read the file.");
        return;
      }

      // Determine sbom_type id if user didn't choose
      let sbom_type = sbomTypeSel ? Number(sbomTypeSel) : null;
      if (!sbom_type) {
        sbom_type = inferSbomTypeIdByFilename(file.name, typeList) || null;
      }

      const payload = {
        sbom_name: sbomName || file.name,
        sbom_data: fileText,                
        sbom_type: sbom_type,               
        projectid: Number(projectId),
        sbom_version: sbomVersion || null,
        created_by: createdBy || null,
        productver: productVer || null,
      };
//  INLINE DUPLICATE SBOM NAME CHECK
const sboms = await api.get("/api/sboms");

const duplicate = sboms.some(s =>
  Number(s.projectid) === payload.projectid &&
  (s.sbom_name || "").toLowerCase() === payload.sbom_name.toLowerCase()
);

if (duplicate) {
  setFieldError(
    "err_sbom_name",
    "SBOM name already exists. Please choose a different name."
  );
  $("#sbomName").addClass("duplicate");
  return; //  STOP upload, stay on same page
}
      try {
        await api.post("/api/sboms", payload);
        toast("SBOM uploaded, saved, and analyzed", "success");
        e.currentTarget.reset();

        // Refresh Analysis Runs table (Refresh button no longer exists)
        if ($("#tblAnalysis").length) {
          $("#tblAnalysis").jtable("reload");
        }

        if ($("#tblSboms").data("initialized")) {
          // Optional: auto-set the SBOMs filter to created_by if empty
          if (createdBy && !$("#filterUserId").val()) {
            $("#filterUserId").val(createdBy);
          }
          $("#tblSboms").jtable("reload");
        }
      } catch (err) {
        console.error(err);
        toast(err.message || "Upload failed", "error");
      }
    });

    // Clear error on input/change
    $("#sbomFile").on("change", () => clearFieldError("err_sbom_file"));
    
$("#sbomName").on("input", () => {
  clearFieldError("err_sbom_name");
  $("#sbomName").removeClass("duplicate");
});
    $("#projectSelect").on("change", () => clearFieldError("err_project_select"));
    $("#createdBy").on("input", () => clearFieldError("err_created_by_upload"));

    // Pre-fill SBOM Name when file picked
    $("#sbomFile").on("change", (e) => {
      const f = e.currentTarget.files[0];
      if (f && !$("#sbomName").val()) {
        $("#sbomName").val(f.name);
      }
    });
  }

  function initSbomsTable() {
    // Clear User ID error as user types
    $("#filterUserId").on("input", () => clearFieldError("filterUserIdError"));

    $("#tblSboms").jtable({
      title: "SBOMs",
      paging: true,
      pageSize: 5,
      gotoPageAreaVisible: false,
      sorting: true,
      defaultSorting: "id DESC",
        actions: {
          listAction: function (postData, jtParams) {
            const userId = $("#filterUserId").val().trim();

            // Inline validation...
            clearFieldError("filterUserIdError");
            if (!userId) {
              setFieldError("filterUserIdError", "User ID is required.");
              const d = new $.Deferred();
              d.resolve({ Result: "OK", Records: [], TotalRecordCount: 0 });
              return d;
            }
            if (!USER_ID_REGEX.test(userId)) {
            setFieldError("filterUserIdError", "Invalid user_id. Only letters, digits, '_', '-', '.' allowed (1–64).");
              const d = new $.Deferred();
              d.resolve({ Result: "OK", Records: [], TotalRecordCount: 0 });
              return d;
            }

            const paging = Object.assign({}, postData, jtParams);
            return jtableWrapList(() => api.get(`/api/sboms?user_id=${encodeURIComponent(userId)}`), paging);
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
        sbom_name: { title: "SBOM Name" },
        sbom_version: { title: "Version", width: "10%" },
        projectid: { title: "Project ID", width: "10%" },
        sbom_type: { title: "Type ID", width: "8%" },
        created_by: { title: "Created By", width: "12%" },
        created_on: { title: "Created On", width: "14%" },
        // ===== Analyze =====
        analyze: {
          title: "Analyze",
          sorting: false,
          width: "9%",
          display: function (data) {
            const $btn = $('<button type="button" class="mini-btn">Analyze</button>')
            $btn.on("click", async () => {

              const sbomId = data.record.id;
              const label = data.record.sbom_name || `#${sbomId}`;

              //  Navigate first
              $(".tab").removeClass("active");
              $("#tab-analysis").addClass("active");
              $(".tablink").removeClass("active");
              $('.tablink[data-target="#tab-analysis"]').addClass("active");

              //  Show popup in analysis tab
              showAnalyzingDialog(`Analyzing SBOM ${label}...`);

              //  Start timer
              let seconds = 0;
              const timerInterval = setInterval(() => {
                seconds++;
                $("#analysisTimer").text(seconds + "s");
              }, 1000);

              //  Make backend call but DO NOT WAIT for response
              api.post(`/api/sboms/${sbomId}/analyze`, {})
                .catch(err => console.error("Analysis start error:", err));

              //  Wire cancel button (frontend only)
              $("#cancelAnalysisBtn").off("click").on("click", () => {
                clearInterval(timerInterval);
                hideAnalyzingDialog();
                toast("Analysis canceled (frontend only)", "error");
              });

              //  Auto-check the Analysis Runs table every 4 seconds
              const reloadInterval = setInterval(() => {
                $("#tblAnalysis").jtable("reload");
              }, 4000);

              //  Auto-stop reload when dialog closes
              $("#__analyzingDialog").on("dialogclose", () => {
                clearInterval(reloadInterval);
              });

            });

            return $btn;
          }
        },
              // ===== Edit column =====
        edit: {
          title: "Edit",
          sorting: false,
          width: "8%",
          display: function (data) {
            const rec = data.record;
            const id = rec.id;
            const $btn = $('<button type="button" class="mini-btn">Edit</button>');
            $btn.on("click", async function () {
              // Prefill dialog fields
              $("#editSbomId").val(id);
              $("#editSbomName").val(rec.sbom_name || "");
              $("#editSbomVersion").val(rec.sbom_version || "");
              $("#editProductVer").val(rec.productver || rec.product_version || "");
              $("#editSbomType").val(rec.sbom_type || "");
              $("#editModifiedBy").val(rec.modified_by || "");
              
              // Clear any old inline errors in dialog
              clearFieldError("err_edit_sbom_name");
              clearFieldError("err_edit_sbom_version");
              clearFieldError("err_edit_product_name");
              clearFieldError("err_edit_product_ver");
              clearFieldError("err_edit_sbom_type");
              clearFieldError("err_edit_modified_by");

              
              // Load SBOM types into the edit dropdown
              await loadTypesToSelect($("#editSbomType"));
              $("#editSbomType").val(rec.sbom_type || ""); // reselect value after load

              // Open dialog and wire Save
              $("#dialogEditSbom").dialog({
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
                      const id = $("#editSbomId").val();
                      const $tbl = $("#tblSboms");
                      const userId = $("#filterUserId").val().trim(); // required by backend
                      
                      // Clear field errors
                      clearFieldError("err_edit_sbom_name");
                      clearFieldError("err_edit_product_name");
                      clearFieldError("err_edit_modified_by");
                      
                      // PATCH requires user_id (must match SBOM.created_by) - we take it from filter
                      clearFieldError("filterUserIdError");
                      if (!userId) {
                        setFieldError("filterUserIdError", "User ID is required for update.");
                        return;
                      }
                      if (!USER_ID_REGEX.test(userId)) {
                        setFieldError("filterUserIdError", "Invalid user_id. Only letters, digits, '_', '-', '.' allowed (1–64).");
                        return;
                      }

                      const payload = {
                        sbom_name: $("#editSbomName").val().trim(),
                        sbom_version: $("#editSbomVersion").val().trim() || null,
                        productver: $("#editProductVer").val().trim() || null,
                        sbom_type: $("#editSbomType").val().trim()
                          ? Number($("#editSbomType").val().trim())
                          : null,
                        modified_by: $("#editModifiedBy").val().trim(),
                        // (Optional) Add projectid if you add a select: projectid: Number($("#editProjectSelect").val()) || null,
                      };

                      let hasError = false;
                      if (!payload.sbom_name) {
                        setFieldError("err_edit_sbom_name", "SBOM Name is required.");
                        hasError = true;
                      }                      
                      if (!payload.modified_by) {
                        setFieldError("err_edit_modified_by", "Modified By is required.");
                        hasError = true;
                      }
                      if (!userId) {
                        setFieldError("filterUserIdError", "User Id is required.");
                        hasError = true;
                      }
                      if (hasError) return;

                      try {
                        const qs = `?user_id=${encodeURIComponent(userId)}`;
                        await api.patch(`/api/sboms/${encodeURIComponent(id)}${qs}`, payload);
                        $(this).dialog("close");
                        toast("SBOM updated successfully", "success");
                        $tbl.jtable("reload");
                      } catch (err) {
                        console.error(err);
                        toast(err.message || "Update failed", "error");
                      }
                    }
                  }
                ]
              });
            });
            return $btn;
          }
        },
              // ===== Delete column =====
        delete_action: {
          title: "Delete",
          sorting: false,
          width: "8%",
          display: function (data) {
            const id = data.record.id;
            const $btn = $('<button type="button" class="mini-btn" style="color:#c0392b;">Delete</button>');
            $btn.on("click", function () {

              $("#dialogConfirmMessage").text(
                `Are you sure you want to delete SBOM “${data.record.sbom_name || id}”? This action cannot be undone.`
              );
              $("#dialogConfirm").dialog({
                modal: true,
                resizable: false,
                buttons: [
                  { text: "Cancel", class: "btn-secondary", click: function () { $(this).dialog("close"); } },
                  {
                    text: "Delete",
                    class: "btn-danger",
                    click: async function () {
                      $(this).dialog("close");
                      const $tbl = $("#tblSboms");

                      // Validate user_id inline (from filter)
                      const userId = $("#filterUserId").val().trim();
                      clearFieldError("filterUserIdError");
                      if (!userId) {
                        setFieldError("filterUserIdError", "User ID is required for deletion.");
                        return;
                      }
                      if (!USER_ID_REGEX.test(userId)) {
                        setFieldError("filterUserIdError", "Invalid user_id. Only letters, digits, '_', '-', '.' allowed (1–64).");
                        return;
                      }

                      try {
                        const params = new URLSearchParams({ user_id: userId, confirm: "yes" });
                        await api.delete(`/api/sboms/${encodeURIComponent(id)}?${params.toString()}`);
                        toast("Successfully deleted", "success");
                        $tbl.jtable("reload");
                      } catch (err) {
                        console.error(err);
                        toast(err.message || "Delete failed", "error");
                      }
                    }
                  }
                ]
              });
            });
            return $btn;
          }
        }
      }
    });
    $("#tblSboms").data("initialized", true);

    $("#formFilterSboms").on("submit", (e) => {
      e.preventDefault();
      clearFieldError("filterUserIdError");
      $("#tblSboms").jtable("load");
    });
  }

  return {
    async init() {
      await ProjectsUI.loadProjectsToSelect($("#projectSelect"));
      await loadTypesToSelect($("#sbomTypeSelect"));
      bindUploadForm();
      initSbomsTable();
    }
  };
})(); 