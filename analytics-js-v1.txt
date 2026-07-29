// analytics.js — Solaries Analytics page (Phase 4)
// Renders live stats, a 30-day loads chart (inline SVG), top scripts, and recent activity.

const el = {
  loads7: document.querySelector('[data-stat="loads7"]'),
  loads30: document.querySelector('[data-stat="loads30"]'),
  uniq: document.querySelector('[data-stat="uniq"]'),
  top: document.querySelector('[data-stat="top"]'),
  topMeta: document.querySelector('[data-stat-meta="top"]'),
  chartSvg: document.getElementById("chartSvg"),
  chartEmpty: document.getElementById("chartEmpty"),
  topTable: document.getElementById("topTable"),
  topBody: document.getElementById("topBody"),
  topEmpty: document.getElementById("topEmpty"),
  activityList: document.getElementById("activityList"),
  activityEmpty: document.getElementById("activityEmpty"),
};

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

  const W = 600;
  const H = 220;
  const padL = 34;
  const padR = 12;
  const padT = 12;
  const padB = 28;
  const innerW = W - padL - padR;
  const innerH = H - padT - padB;
  const n = series.length;
  const maxVal = Math.max.apply(null, series.map(function (p) { return p.count; }));
  const yMax = Math.max(4, Math.ceil(maxVal * 1.15));

  // Grid + Y labels (4 gridlines)
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

  // Points to path
  const step = innerW / (n - 1 || 1);
  const points = series.map(function (p, i) {
    const x = padL + i * step;
    const y = padT + innerH - (p.count / yMax) * innerH;
    return { x: x, y: y };
  });

  // Area fill
  let area = "M" + points[0].x + "," + (padT + innerH);
  points.forEach(function (p) { area += " L" + p.x.toFixed(1) + "," + p.y.toFixed(1); });
  area += " L" + points[points.length - 1].x + "," + (padT + innerH) + " Z";
  const areaPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
  areaPath.setAttribute("d", area);
  areaPath.setAttribute("fill", "rgba(124, 58, 237, 0.18)");
  svg.appendChild(areaPath);

  // Line
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

  // Dots on non-zero days
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

  // X labels — every ~5 days
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
    let tag = "";
    if (a.event === "login") {
      title = "Signed in";
      tag = "LOGIN";
    } else if (a.event === "load") {
      title = a.script_name
        ? "Loaded " + escapeHtml(a.script_name)
        : "Script load";
      if (a.project_name) title += ' <span class="activity-tag">' + escapeHtml(a.project_name) + '</span>';
      tag = "LOAD";
    } else {
      title = a.event;
      tag = a.event.toUpperCase();
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
    if (a.top_project) {
      el.top.textContent = a.top_project.name;
      el.topMeta.textContent = a.top_project.loads + " load" + (a.top_project.loads === 1 ? "" : "s") + " in 30d";
    } else {
      el.top.textContent = "—";
      el.topMeta.textContent = "No traffic yet";
    }

    renderChart(a.series || []);
    renderTopScripts(a.top_scripts || []);
    renderActivity(a.activity || []);
  } catch (e) {
    window.SL.toast(e.message, "error");
  }
}

load();
