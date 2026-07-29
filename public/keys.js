// keys.js — Solaries Keys management (Phase 3)
// Account-scoped keys with optional per-project binding.

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

function formatDate(v) {
  if (!v) return "-";
  const d = new Date(v);
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
}

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
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
  // Filter dropdown on toolbar
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

  // Modal dropdown
  el.kProject.innerHTML = '<option value="">Global — works for any project</option>';
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

  // Filter by status tab
  if (filter === "active") list = list.filter(function (k) { return !k.revoked; });
  if (filter === "revoked") list = list.filter(function (k) { return k.revoked; });

  // Filter by project
  if (projFilter === "global") list = list.filter(function (k) { return !k.project_id; });
  else if (projFilter !== "all") list = list.filter(function (k) { return k.project_id === projFilter; });

  // Search
  if (term) {
    list = list.filter(function (k) {
      return k.key.toLowerCase().includes(term) || (k.label || "").toLowerCase().includes(term);
    });
  }

  // Tab counts
  document.querySelector('[data-count="all"]').textContent = keys.length;
  document.querySelector('[data-count="active"]').textContent = keys.filter(function (k) { return !k.revoked; }).length;
  document.querySelector('[data-count="revoked"]').textContent = keys.filter(function (k) { return k.revoked; }).length;

  el.body.innerHTML = "";
  if (list.length === 0) {
    el.table.style.display = "none";
    if (keys.length === 0) {
      el.empty.style.display = "block";
    } else {
      el.empty.style.display = "none";
      const p = document.createElement("p");
      p.style.cssText = "text-align:center;color:var(--text-soft);padding:32px;";
      p.textContent = "No keys match your filter.";
      el.body.parentNode.appendChild(p);
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

    tr.innerHTML =
      '<td><span class="key-code">' + escapeHtml(k.key) + '</span></td>' +
      '<td>' + escapeHtml(k.label || "—") + '</td>' +
      '<td>' + scope + '</td>' +
      '<td><span class="status-pill ' + (k.revoked ? "is-revoked" : "is-live") + '">' + (k.revoked ? "Revoked" : "Active") + '</span></td>' +
      '<td style="color:var(--text-soft)">' + formatDate(k.created_at) + '</td>' +
      '<td>' +
        '<div class="row-actions">' +
          '<button class="mini-btn" data-copy>Copy</button>' +
          '<button class="mini-btn is-danger" data-toggle>' + (k.revoked ? "Restore" : "Revoke") + '</button>' +
          '<button class="mini-btn is-danger" data-del>Delete</button>' +
        '</div>' +
      '</td>';

    tr.querySelector("[data-copy]").addEventListener("click", async function (e) {
      try {
        await navigator.clipboard.writeText(k.key);
        e.target.textContent = "Copied";
        setTimeout(function () { e.target.textContent = "Copy"; }, 1200);
      } catch (err) {
        window.SL.toast("Copy failed", "error");
      }
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

    el.body.appendChild(tr);
  });
}

// Filters
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

// Generate modal
function openGen() {
  el.kLabel.value = "";
  el.kPrefix.value = "KF";
  el.kProject.value = "";
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
    };
    if (el.kProject.value) body.project_id = el.kProject.value;
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

// New key modal
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
