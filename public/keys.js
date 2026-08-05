// keys.js - Solaries Keys page (mobile responsive)
// Card-based layout for all screen sizes. Pure ASCII only.

const el = {
  total: document.querySelector('[data-stat="total"]'),
  active: document.querySelector('[data-stat="active"]'),
  revoked: document.querySelector('[data-stat="revoked"]'),
  logins: document.querySelector('[data-stat="logins"]'),

  list: document.getElementById("keysList"),
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
  const opts = Array.from(el.projectFilter.options);
  if (opts.some(function (o) { return o.value === currentFilter; })) {
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

  el.list.innerHTML = "";

  if (list.length === 0) {
    if (keys.length === 0) {
      el.empty.style.display = "block";
    } else {
      el.empty.style.display = "none";
      const p = document.createElement("p");
      p.style.cssText = "text-align:center;color:var(--text-soft);padding:32px;font-size:13px;";
      p.textContent = "No keys match your filter.";
      el.list.appendChild(p);
    }
    return;
  }
  el.empty.style.display = "none";

  list.forEach(function (k) {
    const pName = projectName(k.project_id);
    const scopeChip = pName
      ? '<span class="key-scope-chip"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7h7l2 2h9v10a1 1 0 01-1 1H4a1 1 0 01-1-1V7z"/></svg>' + escapeHtml(pName) + '</span>'
      : '<span class="key-scope-chip">Global</span>';

    let lockBadge;
    if (k.hwid_locked) {
      if (k.hwid) {
        lockBadge = '<span class="lock-badge lock-yes"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/></svg> Locked</span>';
      } else {
        lockBadge = '<span class="lock-badge lock-no"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 118 0"/></svg> Awaiting</span>';
      }
    } else {
      lockBadge = '<span class="lock-badge lock-open">Open</span>';
    }

    let expiryText = "Lifetime";
    let expiryClass = "dim";
    if (k.expires_at) {
      const days = Math.ceil((new Date(k.expires_at).getTime() - Date.now()) / 86400000);
      if (days > 0) {
        expiryText = formatDate(k.expires_at) + " (" + days + "d)";
        expiryClass = "";
      } else {
        expiryText = "Expired " + formatDate(k.expires_at);
        expiryClass = "dim";
      }
    }

    let statusPill;
    if (k.revoked) {
      statusPill = '<span class="status-pill is-revoked">Revoked</span>';
    } else if (isExpired(k)) {
      statusPill = '<span class="status-pill is-off">Expired</span>';
    } else {
      statusPill = '<span class="status-pill is-live">Active</span>';
    }

    const resetBtn = k.hwid_locked && k.hwid
      ? '<button class="mini-btn" data-reset type="button">Reset HWID</button>'
      : '';

    const card = document.createElement("div");
    card.className = "key-card";
    card.innerHTML =
      '<div class="key-card-head">' +
        '<span class="key-card-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="14" r="3"/><path d="M11 14h9"/><path d="M17 11v6"/></svg></span>' +
        '<div class="key-card-body">' +
          '<span class="key-code">' + escapeHtml(k.key) + '</span>' +
          '<p class="key-label">' + escapeHtml(k.label || "No label") + '</p>' +
        '</div>' +
        statusPill +
      '</div>' +

      '<div class="key-meta">' +
        '<div class="key-meta-item" style="flex:1 1 45%">' +
          '<span class="key-meta-label">Project</span>' +
          '<span class="key-meta-value">' + scopeChip + '</span>' +
        '</div>' +
        '<div class="key-meta-item" style="flex:1 1 45%">' +
          '<span class="key-meta-label">HWID</span>' +
          '<span class="key-meta-value">' + lockBadge + '</span>' +
        '</div>' +
        '<div class="key-meta-item" style="flex:1 1 100%">' +
          '<span class="key-meta-label">Expiry</span>' +
          '<span class="key-meta-value ' + expiryClass + '">' + expiryText + '</span>' +
        '</div>' +
      '</div>' +

      '<div class="key-actions">' +
        '<button class="mini-btn" data-copy type="button">Copy</button>' +
        resetBtn +
        '<button class="mini-btn is-danger" data-toggle type="button">' + (k.revoked ? "Restore" : "Revoke") + '</button>' +
        '<button class="mini-btn is-danger" data-del type="button">Delete</button>' +
      '</div>';

    card.querySelector("[data-copy]").addEventListener("click", async function (e) {
      try {
        await navigator.clipboard.writeText(k.key);
        e.target.textContent = "Copied";
        setTimeout(function () { e.target.textContent = "Copy"; }, 1200);
      } catch (err) { window.SL.toast("Copy failed", "error"); }
    });

    card.querySelector("[data-toggle]").addEventListener("click", async function () {
      try {
        const r = await window.SL.api("/api/keys/" + k.id, {
          method: "PATCH",
          body: JSON.stringify({ revoked: !k.revoked }),
        });
        if (r.ok) { window.SL.toast(k.revoked ? "Key restored" : "Key revoked", "ok"); loadAll(); }
        else window.SL.toast(r.error || "Could not update", "error");
      } catch (e) { window.SL.toast(e.message, "error"); }
    });

    card.querySelector("[data-del]").addEventListener("click", async function () {
      if (!window.confirm("Delete this key permanently?")) return;
      try {
        const r = await window.SL.api("/api/keys/" + k.id, { method: "DELETE" });
        if (r.ok) { window.SL.toast("Key deleted", "ok"); loadAll(); }
        else window.SL.toast(r.error || "Could not delete", "error");
      } catch (e) { window.SL.toast(e.message, "error"); }
    });

    const resetEl = card.querySelector("[data-reset]");
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

    el.list.appendChild(card);
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
  el.kHwidLock.checked = true;
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
