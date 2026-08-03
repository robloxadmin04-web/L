// status.js - Solaries Status page
// Live per-script + per-key status: active / idle / expired / revoked / disabled.
// "active" = a load happened within the last 15 minutes.

const el = {
  scriptsBody: document.getElementById("scriptsBody"),
  scriptsEmpty: document.getElementById("scriptsEmpty"),
  scriptsCard: document.getElementById("scriptsCard"),
  keysBody: document.getElementById("keysBody"),
  keysEmpty: document.getElementById("keysEmpty"),
  keysCard: document.getElementById("keysCard"),
  refreshBtn: document.getElementById("refreshBtn"),
  tabs: document.querySelectorAll(".st-tab"),
};

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function timeAgo(v) {
  if (!v) return "Never";
  const diff = Math.max(0, Date.now() - new Date(v).getTime());
  const sec = Math.round(diff / 1000);
  if (sec < 60) return sec + "s ago";
  const min = Math.round(sec / 60);
  if (min < 60) return min + "m ago";
  const hr = Math.round(min / 60);
  if (hr < 24) return hr + "h ago";
  return Math.round(hr / 24) + "d ago";
}

function fmtDate(v) {
  if (!v) return "Never";
  const d = new Date(v);
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
}

function badge(status) {
  const map = {
    active: "Active",
    idle: "Idle",
    expired: "Expired",
    revoked: "Revoked",
    disabled: "Disabled",
  };
  const label = map[status] || status;
  return '<span class="status-badge st-' + status + '"><span class="dot"></span>' + label + "</span>";
}

function renderScripts(scripts) {
  el.scriptsBody.innerHTML = "";
  if (!scripts || scripts.length === 0) {
    el.scriptsEmpty.style.display = "block";
    return;
  }
  el.scriptsEmpty.style.display = "none";

  // active first, then idle, then disabled
  const order = { active: 0, idle: 1, disabled: 2 };
  scripts.sort(function (a, b) { return (order[a.status] || 9) - (order[b.status] || 9); });

  scripts.forEach(function (s) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td><strong>" + escapeHtml(s.name) + "</strong><br><span class='st-mono'>" + escapeHtml(s.slug) + "</span></td>" +
      "<td>" + escapeHtml(s.project_name) + "</td>" +
      "<td>" + badge(s.status) + "</td>" +
      "<td>" + s.loads_24h + "</td>" +
      "<td>" + s.unique_devices_24h + "</td>" +
      "<td class='st-mono'>" + timeAgo(s.last_used_at) + "</td>";
    el.scriptsBody.appendChild(tr);
  });
}

function renderKeys(keys) {
  el.keysBody.innerHTML = "";
  if (!keys || keys.length === 0) {
    el.keysEmpty.style.display = "block";
    return;
  }
  el.keysEmpty.style.display = "none";

  const order = { active: 0, idle: 1, expired: 2, revoked: 3 };
  keys.sort(function (a, b) { return (order[a.status] || 9) - (order[b.status] || 9); });

  keys.forEach(function (k) {
    const hwid = k.hwid_locked ? (k.hwid_bound ? "Bound" : "Not bound") : "Off";
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td class='st-mono'>" + escapeHtml(k.key) + "</td>" +
      "<td>" + escapeHtml(k.label || "-") + "</td>" +
      "<td>" + escapeHtml(k.project_name) + "</td>" +
      "<td>" + badge(k.status) + "</td>" +
      "<td class='st-mono'>" + hwid + "</td>" +
      "<td class='st-mono'>" + (k.expires_at ? fmtDate(k.expires_at) : "Never") + "</td>" +
      "<td class='st-mono'>" + timeAgo(k.last_used_at) + "</td>";
    el.keysBody.appendChild(tr);
  });
}

async function load() {
  try {
    const r = await window.SL.api("/api/status");
    if (!r.ok) throw new Error(r.error || "Could not load status");
    renderScripts(r.scripts || []);
    renderKeys(r.keys || []);
  } catch (e) {
    window.SL.toast(e.message, "error");
  }
}

// Tab switching
el.tabs.forEach(function (t) {
  t.addEventListener("click", function () {
    el.tabs.forEach(function (x) { x.classList.remove("is-active"); });
    t.classList.add("is-active");
    const view = t.getAttribute("data-view");
    el.scriptsCard.style.display = view === "scripts" ? "" : "none";
    el.keysCard.style.display = view === "keys" ? "" : "none";
  });
});

el.refreshBtn.addEventListener("click", load);

// Auto-refresh every 30s
load();
setInterval(load, 30000);
