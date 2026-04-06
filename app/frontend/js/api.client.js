// js/api.client.js
const API_BASE = window.SBOM_API_BASE || "http://localhost:8000";

// === Shared: same allowlist as backend (letters, digits, underscore, hyphen, dot; 1–64) ===
const USER_ID_REGEX = /^[A-Za-z0-9_.-]{1,64}$/;

// === Inline error helpers ===
function setFieldError(id, message) {
  const $el = typeof id === "string" ? $(`#${id}`) : id;
  if ($el && $el.length) $el.text(message || "");
}
function clearFieldError(id) {
  setFieldError(id, "");
}
async function parseApiError(resp, method, path) {
  let details = "";
  try {
    const contentType = resp.headers.get("Content-Type") || "";
    if (contentType.includes("application/json")) {
      const body = await resp.json();
      if (typeof body === "string") {
        details = ` - ${body}`;
      } else if (body && typeof body === "object") {
        if (Array.isArray(body.detail)) {
          const msgs = body.detail.map(e => {
            if (typeof e === "string") return e;
            if (e && typeof e === "object") {
              const loc = Array.isArray(e.loc) ? e.loc.join(".") : e.loc;
              return `${e.msg}${loc ? ` (loc: ${loc})` : ""}`;
            }
            return String(e);
          });
          details = ` - ${msgs.join("; ")}`;
        } else if (typeof body.detail === "string") {
          details = ` - ${body.detail}`;
        } else if (body.message) {
          details = ` - ${body.message}`;
        } else {
          details = ` - ${JSON.stringify(body)}`;
        }
      }
    } else {
      const text = await resp.text().catch(() => "");
      details = text ? ` - ${text}` : "";
    }
  } catch (_) { /* ignore parse errors */ }
  return new Error(`${method} ${path} failed: ${resp.status}${details}`);
}
 
// Simple wrapper around fetch with JSON handling
// js/api.client.js

const api = {
  async get(path) {
    const resp = await fetch(`${API_BASE}${path}`, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Cache-Control": "no-cache"
      },
      cache: "no-store", // ⬅️ prevent browser caching
    });
    if (!resp.ok) throw await parseApiError(resp, "GET", path);
    return resp.json();
  },

  async post(path, data) {
    const resp = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(data),
    });
    if (!resp.ok) throw await parseApiError(resp, "POST", path);
    return resp.json();
  },

  async patch(path, data) {
    const resp = await fetch(`${API_BASE}${path}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(data),
    });
    if (!resp.ok) throw await parseApiError(resp, "PATCH", path);
    try {
      return await resp.json();
    } catch {
      return { ok: true };
    }
  },

  // (Optional) PUT if your backend prefers it:
  async put(path, data) {
    const resp = await fetch(`${API_BASE}${path}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(data),
    });
    if (!resp.ok) throw await parseApiError(resp, "PUT", path);
    try {
      return await resp.json();
    } catch {
      return { ok: true };
    }
  },

  // DELETE (supports returning 204 or JSON)
  async delete(path) {
    const resp = await fetch(`${API_BASE}${path}`, {
      method: "DELETE",
      headers: { "Accept": "application/json" },
    });
    if (!resp.ok) throw await parseApiError(resp, "DELETE", path);
    if (resp.status === 204) return { ok: true };
    try {
      return await resp.json();
    } catch {
      return { ok: true };
    }
  },
};

// Helper: Wrap a promise-producing function to jTable's expected return
// jTable expects: { Result: "OK", Records: [...], TotalRecordCount: n }
// Now supports client-side sorting + paging using jt params.
function jtableWrapList(promiseFactory, jtParams = {}, options = {}) {
  const d = new $.Deferred();

  const getVal = (obj, path) => {
    if (!obj || !path) return undefined;
    return path.split('.').reduce((o, k) => (o ? o[k] : undefined), obj);
  };

  const smartCompare = (a, b) => {
    const an = a === null || a === undefined;
    const bn = b === null || b === undefined;
    if (an && bn) return 0;
    if (an) return 1;
    if (bn) return -1;

    const na = Number(a);
    const nb = Number(b);
    const aIsNum = Number.isFinite(na);
    const bIsNum = Number.isFinite(nb);
    if (aIsNum && bIsNum) return na - nb;

    const da = Date.parse(a);
    const db = Date.parse(b);
    const aIsDate = Number.isFinite(da);
    const bIsDate = Number.isFinite(db);
    if (aIsDate && bIsDate) return da - db;

    return String(a).localeCompare(String(b), undefined, { sensitivity: 'base', numeric: true });
  };

  promiseFactory()
    .then(fullList => {
      const list = Array.isArray(fullList) ? [...fullList] : [];

      const startIndex = parseInt(jtParams.jtStartIndex ?? 0, 10) || 0;
      const pageSize  = parseInt(jtParams.jtPageSize  ?? list.length, 10) || list.length;
      const sorting   = (jtParams.jtSorting || '').trim(); // e.g., "id DESC"

      const fieldMap = options.fieldMap || {};

      if (sorting) {
        const m = sorting.match(/^(\S+)\s+(ASC|DESC)$/i);
        if (m) {
          const field = m[1];
          const dir = m[2].toUpperCase();
          const prop = fieldMap[field] || field;
          list.sort((x, y) => {
            const cmp = smartCompare(getVal(x, prop), getVal(y, prop));
            return dir === 'DESC' ? -cmp : cmp;
          });
        }
      }

      const total = list.length;
      const pageRecords = list.slice(startIndex, startIndex + pageSize);

      d.resolve({
        Result: "OK",
        Records: pageRecords,
        TotalRecordCount: total
      });
    })
    .catch(err => d.reject(err));

  return d;
}
// small toast (kept for server success/failure messages)
function toast(msg, type = "info") {
  const $t = $(`<div class="toast ${type}">${msg}</div>`).appendTo("body");
  setTimeout(() => $t.fadeOut(400, () => $t.remove()), 2400);
}

const ApiClient = {
  ...api,

  getDashboardStats() {
    return api.get("/dashboard/stats");
  },

  getRecentSboms(limit = 5) {
    return api.get(`/dashboard/recent-sboms?limit=${limit}`);
  },

  getActivityStats() {
    return api.get("/dashboard/activity");
  },

  getSeveritySummary() {
    return api.get("/dashboard/severity");
  }
};
 