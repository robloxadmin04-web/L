// analytics.js — Solaries Analytics page (Phase 5 — breakdown, blocked, range toggle, clear logs)
// Renders live stats, a loads chart (inline SVG, 7d/30d), top scripts, block reasons,
// event breakdown, and a scrollable recent-activity feed with a Clear Logs action.

const el = {
  loads7: document.querySelector('[data-stat="loads7"]'),
  loads30: document.querySelector('[data-stat="loads30"]'),
  uniq: document.querySelector('[data-stat="uniq"]'),
  blocked7: document.querySelector('[data-stat="blocked7"]'),
  top: document.querySelector('[data-stat="top"]'),
  topMeta: document.querySelector('[data-stat-meta="top"]'),
  chartSvg: document.getElementById("chartSvg"),
  chartEmpty: document.getElementById("chartEmpty"),
  chartTitle: document.getElementById("chartTitle"),
  rangeToggle: document.getElementById("rangeToggle"),
  bdLoad: document.querySelector('[data-bd="load"]'),
  bdLogin: document.querySelector('[data-bd="login"]'),
  bdBlocked: document.querySelector('[data-bd="blocked"]'),
  topTable: document.getElementById("topTable"),
  topBody: document.getElementById("topBody"),
  topEmpty: document.getElementById("topEmpty"),
  reasonSection: document.getElementById("reasonSection"),
  reasonList: document.getElementById("reasonList"),
  activityList: document.getElementById("activityList"),
  activityEmpty: document.getElementById("activityEmpty"),
  refreshBtn: document.getElementById("refreshBtn"),
  clearLogsBtn: document.getElementById("clearLogsBtn"),
  clearModal: document.getElementById("clearModal"),
  closeClear: document.getElementById("closeClear"),
  cancelClear: document.getElementById("cancelClear"),
  confirmClear: document.getElementById("confirmClear"),
};

let currentRange = 30;       // 7 or 30
let lastSeries = [];         // full 30-day series from the server

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function timeAgo(iso) {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  const diff = Math.max(0, Date.now() - then);
  const sec = Math.round(diff / 1000);
  if (sec < 60) return sec + "s ago";
  const min = Math.round(sec / 60);
  if (min < 60) return min + "m ago";
  const hr = Math.round(min / 60);
  if (hr < 24) return hr + "h ago";
  const day = Math.round(hr / 24);
  return day + "d ago";
}

function shortDate(iso) {
  const d = new Date(iso);
  return String(d.getMonth() + 1).padStart(2, "0") + "/" + String(d.getDate()).padStart(2, "0");
}

// ------------------------------------------------------------
// Chart renderer — pure SVG, no external library
// ------------------------------------------------------------
function renderChart(series) {
  const svg = el.chartSvg;
  svg.innerHTML = "";
  const total = series.reduce(function (s, p) { return s + p.count; }, 0);
  if (total === 0) {
    el.chartEmpty.style.display = "block";
    svg.style.display = "none";
    return;
  }
  el.chartEmpty.style.display = "none";
  svg.style.display = "block";

  const W = 600, H = 220;
  const padL = 34, padR = 12, padT = 12, padB = 28;
  const innerW = W - padL - padR;
  const innerH = H - padT - padB;
  const n = series.length;
  const maxVal = Math.max.apply(null, series.map(function (p) { return p.count; }));
  const yMax = Math.max(4, Math.ceil(maxVal * 1.15));

  const gridLines = 4;
  for (let i = 0; i <= gridLines; i++) {
    const y = padT + (innerH * i) / gridLines;
    const val = Math.round(yMax * (1 - i / gridLines));
    const gridLine = document.createElementNS("http://www.w3.org/2000/svg", "line");
    gridLine.setAttribute("x1", padL);
    gridLine.setAttribute("x2", W - padR);
    gridLine.setAttribute("y1", y);
    gridLine.setAttribute("y2", y);
    gridLine.setAttribute("stroke", "#1f2126");
    gridLine.setAttribute("stroke-width", "1");
    svg.appendChild(gridLine);

    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", padL - 6);
    label.setAttribute("y", y + 4);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("fill", "#7c818b");
    label.setAttribute("font-size", "10");
    label.setAttribute("font-family", "Inter, sans-serif");
    label.textContent = String(val);
    svg.appendChild(label);
  }

  const step = innerW / (n - 1 || 1);
  const points = series.map(function (p, i) {
    const x = padL + i * step;
    const y = padT + innerH - (p.count / yMax) * innerH;
    return { x: x, y: y };
  });

  let area = "M" + points[0].x + "," + (padT + innerH);
  points.forEach(function (p) { area += " L" + p.x.toFixed(1) + "," + p.y.toFixed(1); });
  area += " L" + points[points.length - 1].x + "," + (padT + innerH) + " Z";
  const areaPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
  areaPath.setAttribute("d", area);
  areaPath.setAttribute("fill", "rgba(124, 58, 237, 0.18)");
  svg.appendChild(areaPath);

  let line = "M" + points[0].x.toFixed(1) + "," + points[0].y.toFixed(1);
  points.slice(1).forEach(function (p) { line += " L" + p.x.toFixed(1) + "," + p.y.toFixed(1); });
  const linePath = document.createElementNS("http://www.w3.org/2000/svg", "path");
  linePath.setAttribute("d", line);
  linePath.setAttribute("fill", "none");
  linePath.setAttribute("stroke", "#7c3aed");
  linePath.setAttribute("stroke-width", "2");
  linePath.setAttribute("stroke-linecap", "round");
  linePath.setAttribute("stroke-linejoin", "round");
  svg.appendChild(linePath);

  points.forEach(function (p, i) {
    if (series[i].count === 0) return;
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("cx", p.x);
    c.setAttribute("cy", p.y);
    c.setAttribute("r", "2.5");
    c.setAttribute("fill", "#7c3aed");
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = series[i].date + " · " + series[i].count + " load" + (series[i].count === 1 ? "" : "s");
    c.appendChild(title);
    svg.appendChild(c);
  });

  const xLabelStep = Math.ceil(n / 6);
  for (let i = 0; i < n; i += xLabelStep) {
    const p = points[i];
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", p.x);
    label.setAttribute("y", H - 8);
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("fill", "#7c818b");
    label.setAttribute("font-size", "10");
    label.setAttribute("font-family", "Inter, sans-serif");
    label.textContent = shortDate(series[i].date);
    svg.appendChild(label);
  }
}

function applyRange() {
  const sliced = currentRange === 7 ? lastSeries.slice(-7) : lastSeries;
  el.chartTitle.textContent = "Loads per day - last " + currentRange + " days";
  renderChart(sliced);
}

// ------------------------------------------------------------
// Top scripts
// ------------------------------------------------------------
function renderTopScripts(list) {
  el.topBody.innerHTML = "";
  if (!list || list.length === 0) {
    el.topTable.style.display = "none";
    el.topEmpty.style.display = "block";
    return;
  }
  el.topTable.style.display = "";
  el.topEmpty.style.display = "none";

  list.forEach(function (s) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td><div class="cell-name">' + escapeHtml(s.name) + '</div>' +
      '<div class="cell-sub">' + escapeHtml(s.slug) + '</div></td>' +
      '<td>' + escapeHtml(s.project_name) + '</td>' +
      '<td style="text-align:right; color:var(--white); font-weight:600">' + s.loads + '</td>';
    el.topBody.appendChild(tr);
  });
}

// ------------------------------------------------------------
// Block reasons
// ------------------------------------------------------------
function renderReasons(list) {
  el.reasonList.innerHTML = "";
  if (!list || list.length === 0) {
    el.reasonSection.style.display = "none";
    return;
  }
  el.reasonSection.style.display = "block";
  list.forEach(function (r) {
    const row = document.createElement("div");
    row.className = "reason-row";
    row.innerHTML =
      '<span class="r-name">' + escapeHtml(r.reason) + '</span>' +
      '<span class="r-count">' + r.count + '</span>';
    el.reasonList.appendChild(row);
  });
}

// ------------------------------------------------------------
// Activity feed
// ------------------------------------------------------------
function renderActivity(list) {
  el.activityList.innerHTML = "";
  if (!list || list.length === 0) {
    el.activityEmpty.style.display = "block";
    return;
  }
  el.activityEmpty.style.display = "none";

  list.forEach(function (a) {
    const item = document.createElement("div");
    item.className = "activity-item";

    let title = "";
    if (a.event === "login") {
      title = "Signed in";
    } else if (a.event === "load") {
      title = a.script_name ? "Loaded " + escapeHtml(a.script_name) : "Script load";
      if (a.project_name) title += ' <span class="activity-tag">' + escapeHtml(a.project_name) + '</span>';
    } else if (a.event === "blocked") {
      title = "Blocked" + (a.reason ? ": " + escapeHtml(a.reason) : "");
    } else {
      title = escapeHtml(a.event);
    }

    item.innerHTML =
      '<span class="activity-dot ' + escapeHtml(a.event) + '"></span>' +
      '<div class="activity-copy">' +
        '<p class="activity-title">' + title + '</p>' +
        '<p class="activity-time">' + timeAgo(a.created_at) + '</p>' +
      '</div>';
    el.activityList.appendChild(item);
  });
}

// ------------------------------------------------------------
// Load
// ------------------------------------------------------------
async function load() {
  try {
    const r = await window.SL.api("/api/analytics");
    if (!r.ok) throw new Error(r.error || "Could not load analytics");
    const a = r.analytics;

    el.loads7.textContent = a.loads_7d;
    el.loads30.textContent = a.loads_30d;
    el.uniq.textContent = a.unique_keys_24h;
    el.blocked7.textContent = a.blocked_7d || 0;

    if (el.bdLoad) el.bdLoad.textContent = (a.breakdown && a.breakdown.load) || 0;
    if (el.bdLogin) el.bdLogin.textContent = (a.breakdown && a.breakdown.login) || 0;
    if (el.bdBlocked) el.bdBlocked.textContent = (a.breakdown && a.breakdown.blocked) || 0;

    lastSeries = a.series || [];
    applyRange();
    renderTopScripts(a.top_scripts || []);
    renderReasons(a.top_block_reasons || []);
    renderActivity(a.activity || []);
  } catch (e) {
    window.SL.toast(e.message, "error");
  }
}

// ------------------------------------------------------------
// Range toggle
// ------------------------------------------------------------
if (el.rangeToggle) {
  el.rangeToggle.addEventListener("click", function (e) {
    const btn = e.target.closest("button[data-range]");
    if (!btn) return;
    currentRange = parseInt(btn.getAttribute("data-range"), 10);
    el.rangeToggle.querySelectorAll("button").forEach(function (b) {
      b.classList.toggle("is-active", b === btn);
    });
    applyRange();
  });
}

// ------------------------------------------------------------
// Refresh
// ------------------------------------------------------------
if (el.refreshBtn) {
  el.refreshBtn.addEventListener("click", function () {
    el.refreshBtn.style.opacity = "0.5";
    load().finally(function () { el.refreshBtn.style.opacity = ""; });
  });
}

// ------------------------------------------------------------
// Clear logs
// ------------------------------------------------------------
function openClear() { if (el.clearModal) el.clearModal.classList.add("is-open"); }
function closeClearModal() { if (el.clearModal) el.clearModal.classList.remove("is-open"); }

if (el.clearLogsBtn) el.clearLogsBtn.addEventListener("click", openClear);
if (el.closeClear) el.closeClear.addEventListener("click", closeClearModal);
if (el.cancelClear) el.cancelClear.addEventListener("click", closeClearModal);
if (el.clearModal) {
  el.clearModal.addEventListener("click", function (e) {
    if (e.target.hasAttribute("data-close")) closeClearModal();
  });
}
if (el.confirmClear) {
  el.confirmClear.addEventListener("click", async function () {
    el.confirmClear.disabled = true;
    const orig = el.confirmClear.textContent;
    el.confirmClear.textContent = "Deleting...";
    try {
      const r = await window.SL.api("/api/analytics/logs", { method: "DELETE" });
      if (r.ok) {
        window.SL.toast("All logs cleared", "ok");
        closeClearModal();
        await load();
      } else {
        window.SL.toast(r.error || "Could not clear logs", "error");
      }
    } catch (e) {
      window.SL.toast(e.message || "Could not clear logs", "error");
    }
    el.confirmClear.disabled = false;
    el.confirmClear.textContent = orig;
  });
}

load();
