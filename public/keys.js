// keys.js - Solaries Keys page (Phase 6)
// Adds HWID lock toggle, expiry days, Reset HWID button, expiry column.

const el = {
  total: document.querySelector('[data-stat="total"]'),
  active: document.querySelector('[data-stat="active"]'),
  revoked: document.querySelector('[data-stat="revoked"]'),
  logins: document.querySelector('[data-stat="logins"]'),

  table: document.getElementById("keysTable"),
  body: document.getElementById("keysBody"),
  empty: document.getElementById("keysEmpty"),
  search: document.getElementById("searchInput"),
  projectFilter: document.getElementById("projectFilter"),
  tabs: document.querySelectorAll("#filterTabs .tab-btn"),

  openGenerate: document.getElementById("openGenerate"),
  genModal: document.getElementById("genModal"),
  closeGen: document.getElementById("closeGen"),
  cancelGen: document.getElementById("cancelGen"),
  confirmGen: document.getElementById("confirmGen"),
  kLabel: document.getElementById("kLabel"),
  kPrefix: document.getElementById("kPrefix"),
  kProject: document.getElementById("kProject"),
  kExpires: document.getElementById("kExpires"),
  kHwidLock: document.getElementById("kHwidLock"),
  genErr: document.getElementById("genErr"),

  newKeyModal: document.getElementById("newKeyModal"),
  newKeyCode: document.getElementById("newKeyCode"),
  closeNewKey: document.getElementById("closeNewKey"),
  doneNewKey: document.getElementById("doneNewKey"),
  copyNewKey: document.getElementById("copyNewKey"),
};

let keys = [];
let projects = [];
let filter = "all";
let limits = { max_keys: 0 };

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function formatDate(v) {
  if (!v) return "-";
  const d = new Date(v);
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
}

function isExpired(k) {
  return k.expires_at && new Date(k.expires_at).getTime() < Date.now();
}

function projectName(id) {
  if (!id) return null;
  const p = projects.find(function (x) { return x.id === id; });
  return p ? p.name : "(deleted)";
}

async function loadAll() {
  try {
    const [statsRes, projRes, keysRes] = await Promise.all([
      window.SL.api("/api/stats"),
      window.SL.api("/api/projects"),
      window.SL.api("/api/keys"),
    ]);
    if (statsRes.ok) {
      limits = statsRes.limits;
      el.total.textContent = statsRes.stats.keys + " / " + limits.max_keys;
      el.active.textContent = statsRes.stats.active_keys;
      el.revoked.textContent = statsRes.stats.revoked_keys;
      el.logins.textContent = statsRes.stats.logins_24h;
    }
    if (projRes.ok) {
      projects = projRes.projects || [];
      populateProjectFilters();
    }
    if (keysRes.ok) {
      keys = keysRes.keys || [];
      render();
    }
  } catch (e) {
    window.SL.toast(e.message, "error");
  }
}

function populateProjectFilters() {
  const currentFilter = el.projectFilter.value;
  el.projectFilter.innerHTML = '<option value="all">All projects</option><option value="global">Global (no project)</option>';
  projects.forEach(function (p) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = p.name;
    el.projectFilter.appendChild(o);
  });
  if ([...el.projectFilter.options].some(function (o) { return o.value === currentFilter; })) {
    el.projectFilter.value = currentFilter;
  }

  el.kProject.innerHTML = '<option value="">Global (works for any project)</option>';
  projects.forEach(function (p) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = p.name;
    el.kProject.appendChild(o);
  });
}

function render() {
  const term = el.search.value.trim().toLowerCase();
  const projFilter = el.projectFilter.value;

  let list = keys.slice();

  if (filter === "active") list = list.filter(function (k) { return !k.revoked && !isExpired(k); });
  if (filter === "revoked") list = list.filter(function (k) { return k.revoked; });
  if (filter === "expired") list = list.filter(function (k) { return !k.revoked && isExpired(k); });

  if (projFilter === "global") list = list.filter(function (k) { return !k.project_id; });
  else if (projFilter !== "all") list = list.filter(function (k) { return k.project_id === projFilter; });

  if (term) {
    list = list.filter(function (k) {
      return k.key.toLowerCase().includes(term) || (k.label || "").toLowerCase().includes(term);
    });
  }

  document.querySelector('[data-count="all"]').textContent = keys.length;
  document.querySelector('[data-count="active"]').textContent = keys.filter(function (k) { return !k.revoked && !isExpired(k); }).length;
  document.querySelector('[data-count="revoked"]').textContent = keys.filter(function (k) { return k.revoked; }).length;
  document.querySelector('[data-count="expired"]').textContent = keys.filter(function (k) { return !k.revoked && isExpired(k); }).length;

  el.body.innerHTML = "";
  if (list.length === 0) {
    el.table.style.display = "none";
    if (keys.length === 0) {
      el.empty.style.display = "block";
    } else {
      el.empty.style.display = "none";
      const p = document.createElement("tr");
      p.innerHTML = '<td colspan="7" style="text-align:center;color:var(--text-soft);padding:32px;">No keys match your filter.</td>';
      el.body.appendChild(p);
    }
    return;
  }
  el.table.style.display = "";
  el.empty.style.display = "none";

  list.forEach(function (k) {
    const tr = document.createElement("tr");
    const pName = projectName(k.project_id);
    const scope = pName
      ? '<span class="key-scope"><svg viewBox="0 0 24 24"><path d="M3 7h7l2 2h9v10a1 1 0 01-1 1H4a1 1 0 01-1-1V7z"></path></svg>' + escapeHtml(pName) + '</span>'
      : '<span class="key-scope">Global</span>';

    let lockCell;
    if (k.hwid_locked) {
      if (k.hwid) {
        lockCell = '<span class="lock-icon lock-yes" title="Locked to: ' + escapeHtml(k.hwid) + '"><svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 018 0v4"></path></svg> Locked</span>';
      } else {
        lockCell = '<span class="lock-icon lock-no"><svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 118 0"></path></svg> Awaiting</span>';
      }
    } else {
      lockCell = '<span class="lock-no">Open</span>';
    }

    let expiryCell = "Lifetime";
    let statusCell;
    if (k.revoked) {
      statusCell = '<span class="status-pill is-revoked">Revoked</span>';
    } else if (isExpired(k)) {
      statusCell = '<span class="status-pill is-off">Expired</span>';
    } else {
      statusCell = '<span class="status-pill is-live">Active</span>';
    }
    if (k.expires_at) {
      const days = Math.ceil((new Date(k.expires_at).getTime() - Date.now()) / 86400000);
      expiryCell = formatDate(k.expires_at) + (days > 0 ? ' <span style="color:var(--text-soft)">(' + days + 'd)</span>' : ' <span style="color:#fca5a5">(expired)</span>');
    }

    const resetBtn = k.hwid_locked && k.hwid ? '<button class="mini-btn" data-reset>Reset HWID</button>' : '';

    tr.innerHTML =
      '<td><span class="key-code">' + escapeHtml(k.key) + '</span></td>' +
      '<td>' + escapeHtml(k.label || "-") + '</td>' +
      '<td>' + scope + '</td>' +
      '<td>' + lockCell + '</td>' +
      '<td style="color:var(--text-soft)">' + expiryCell + '</td>' +
      '<td>' + statusCell + '</td>' +
      '<td>' +
        '<div class="row-actions">' +
          '<button class="mini-btn" data-copy>Copy</button>' +
          resetBtn +
          '<button class="mini-btn is-danger" data-toggle>' + (k.revoked ? "Restore" : "Revoke") + '</button>' +
          '<button class="mini-btn is-danger" data-del>Delete</button>' +
        '</div>' +
      '</td>';

    tr.querySelector("[data-copy]").addEventListener("click", async function (e) {
      try {
        await navigator.clipboard.writeText(k.key);
        e.target.textContent = "Copied";
        setTimeout(function () { e.target.textContent = "Copy"; }, 1200);
      } catch (err) { window.SL.toast("Copy failed", "error"); }
    });

    tr.querySelector("[data-toggle]").addEventListener("click", async function () {
      try {
        const r = await window.SL.api("/api/keys/" + k.id, {
          method: "PATCH",
          body: JSON.stringify({ revoked: !k.revoked }),
        });
        if (r.ok) { window.SL.toast(k.revoked ? "Key restored" : "Key revoked", "ok"); loadAll(); }
        else window.SL.toast(r.error || "Could not update", "error");
      } catch (e) { window.SL.toast(e.message, "error"); }
    });

    tr.querySelector("[data-del]").addEventListener("click", async function () {
      if (!window.confirm("Delete this key permanently?")) return;
      try {
        const r = await window.SL.api("/api/keys/" + k.id, { method: "DELETE" });
        if (r.ok) { window.SL.toast("Key deleted", "ok"); loadAll(); }
        else window.SL.toast(r.error || "Could not delete", "error");
      } catch (e) { window.SL.toast(e.message, "error"); }
    });

    const resetEl = tr.querySelector("[data-reset]");
    if (resetEl) {
      resetEl.addEventListener("click", async function () {
        if (!window.confirm("Reset HWID for this key? User can bind to a new device on next load.")) return;
        try {
          const r = await window.SL.api("/api/keys/" + k.id + "/reset-hwid", { method: "POST" });
          if (r.ok) { window.SL.toast("HWID reset", "ok"); loadAll(); }
          else window.SL.toast(r.error || "Could not reset", "error");
        } catch (e) { window.SL.toast(e.message, "error"); }
      });
    }

    el.body.appendChild(tr);
  });
}

el.tabs.forEach(function (t) {
  t.addEventListener("click", function () {
    el.tabs.forEach(function (x) { x.classList.remove("is-active"); });
    t.classList.add("is-active");
    filter = t.getAttribute("data-filter");
    render();
  });
});
el.search.addEventListener("input", render);
el.projectFilter.addEventListener("change", render);

function openGen() {
  el.kLabel.value = "";
  el.kPrefix.value = "KF";
  el.kProject.value = "";
  el.kExpires.value = "";
  el.kHwidLock.checked = false;
  el.genErr.classList.remove("is-visible");
  el.genModal.classList.add("is-open");
  setTimeout(function () { el.kLabel.focus(); }, 50);
}
function closeGen() { el.genModal.classList.remove("is-open"); }

el.openGenerate.addEventListener("click", openGen);
el.closeGen.addEventListener("click", closeGen);
el.cancelGen.addEventListener("click", closeGen);
el.genModal.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeGen();
});

el.confirmGen.addEventListener("click", async function () {
  el.confirmGen.disabled = true;
  el.confirmGen.textContent = "Creating...";
  try {
    const body = {
      label: el.kLabel.value.trim(),
      prefix: el.kPrefix.value.trim() || "KF",
      hwid_locked: el.kHwidLock.checked,
    };
    if (el.kProject.value) body.project_id = el.kProject.value;
    if (el.kExpires.value) body.expires_in_days = parseInt(el.kExpires.value, 10);
    const r = await window.SL.api("/api/keys", {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (r.ok) {
      closeGen();
      showNewKey(r.key.key);
      loadAll();
    } else {
      el.genErr.textContent = r.error || "Could not create key.";
      el.genErr.classList.add("is-visible");
    }
  } catch (e) {
    el.genErr.textContent = e.message;
    el.genErr.classList.add("is-visible");
  } finally {
    el.confirmGen.disabled = false;
    el.confirmGen.textContent = "Create key";
  }
});

function showNewKey(k) {
  el.newKeyCode.textContent = k;
  el.newKeyModal.classList.add("is-open");
}
function closeNewKey() { el.newKeyModal.classList.remove("is-open"); }
el.closeNewKey.addEventListener("click", closeNewKey);
el.doneNewKey.addEventListener("click", closeNewKey);
el.newKeyModal.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeNewKey();
});
el.copyNewKey.addEventListener("click", async function () {
  try {
    await navigator.clipboard.writeText(el.newKeyCode.textContent);
    window.SL.toast("Key copied", "ok");
  } catch (e) { window.SL.toast("Copy failed", "error"); }
});

document.addEventListener("keydown", function (e) {
  if (e.key === "Escape") { closeGen(); closeNewKey(); }
});

loadAll();
