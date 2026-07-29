// projects.js â€” Solaries Projects page (Phase 1)
// List view with stats, search, sort, filter tabs, and create modal.

const els = {
  list: document.getElementById("projectsList"),
  empty: document.getElementById("projectsEmpty"),
  search: document.getElementById("searchInput"),
  sort: document.getElementById("sortSelect"),
  tabs: document.querySelectorAll("#filterTabs .tab-btn"),
  openCreate: document.getElementById("openCreate"),
  modal: document.getElementById("createModal"),
  closeCreate: document.getElementById("closeCreate"),
  cancelCreate: document.getElementById("cancelCreate"),
  confirmCreate: document.getElementById("confirmCreate"),
  pName: document.getElementById("pName"),
  pNote: document.getElementById("pNote"),
  createErr: document.getElementById("createErr"),
};

let projects = [];
let filter = "all";
let limits = { max_projects: 0, max_scripts_per_project: 0, max_keys: 0, max_obfuscations_per_month: 0 };

function formatDate(v) {
  if (!v) return "-";
  const d = new Date(v);
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
}

function shortId(id) { return String(id || "").slice(0, 8); }

async function loadAll() {
  try {
    const [statsRes, projRes] = await Promise.all([
      window.SL.api("/api/stats"),
      window.SL.api("/api/projects"),
    ]);
    if (statsRes.ok) {
      limits = statsRes.limits;
      const s = statsRes.stats;
      document.querySelector('[data-stat="projects"]').textContent = s.projects + " / " + limits.max_projects;
      document.querySelector('[data-stat="scripts"]').textContent = s.scripts + " / " + (limits.max_scripts_per_project * Math.max(s.projects, 1));
      document.querySelector('[data-stat="keys"]').textContent = s.keys + " / " + limits.max_keys;
      document.querySelector('[data-stat="obf"]').textContent = "0 / " + limits.max_obfuscations_per_month;
      const meta = document.querySelector('[data-stat-meta="scripts"]');
      if (meta) meta.textContent = "Up to " + limits.max_scripts_per_project + " per project";
    }
    if (projRes.ok) {
      projects = projRes.projects || [];
      render();
    }
  } catch (e) {
    window.SL.toast(e.message, "error");
  }
}

function render() {
  const term = els.search.value.trim().toLowerCase();
  const sortMode = els.sort.value;

  let list = projects.slice();
  if (filter === "owned") list = list; // all are owned for now (shared is Phase 2)
  if (filter === "shared") list = [];

  if (term) {
    list = list.filter(function (p) {
      return p.name.toLowerCase().includes(term) || (p.note || "").toLowerCase().includes(term) || p.slug.toLowerCase().includes(term);
    });
  }

  if (sortMode === "name") list.sort(function (a, b) { return a.name.localeCompare(b.name); });
  else if (sortMode === "scripts") list.sort(function (a, b) { return (b.script_count || 0) - (a.script_count || 0); });
  else list.sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); });

  // Tab counts
  document.querySelector('[data-count="all"]').textContent = projects.length;
  document.querySelector('[data-count="owned"]').textContent = projects.length;
  document.querySelector('[data-count="shared"]').textContent = 0;

  els.list.innerHTML = "";
  if (list.length === 0) {
    els.empty.style.display = projects.length === 0 ? "block" : "none";
    if (projects.length > 0) {
      const p = document.createElement("p");
      p.style.cssText = "text-align:center;color:var(--text-soft);padding:32px;";
      p.textContent = "No projects match your search.";
      els.list.appendChild(p);
    }
    return;
  }
  els.empty.style.display = "none";

  list.forEach(function (p) {
    const row = document.createElement("div");
    row.className = "project-row";
    row.innerHTML =
      '<div class="project-row-head">' +
        '<span class="project-caret"><svg viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"></path></svg></span>' +
        '<span class="project-icon"><svg viewBox="0 0 24 24"><path d="M3 7h7l2 2h9v10a1 1 0 01-1 1H4a1 1 0 01-1-1V7z"></path></svg></span>' +
        '<div class="project-info">' +
          '<div class="project-name-row">' +
            '<span class="project-name">' + escapeHtml(p.name) + '</span>' +
            '<span class="status-pill ' + (p.status === "paused" ? "is-paused" : "is-live") + '">' + (p.status === "paused" ? "Paused" : "Active") + '</span>' +
          '</div>' +
          '<div class="project-meta"><code>' + escapeHtml(shortId(p.id)) + '</code> &middot; ' + (p.script_count || 0) + ' script' + ((p.script_count || 0) === 1 ? "" : "s") + ' &middot; ' + (p.key_count || 0) + ' key' + ((p.key_count || 0) === 1 ? "" : "s") + '</div>' +
        '</div>' +
        '<div class="project-actions">' +
          '<button class="mini-btn is-primary" data-open>Open</button>' +
          '<button class="mini-btn is-danger" data-delete>Delete</button>' +
        '</div>' +
      '</div>' +
      '<div class="project-row-body">' +
        '<p style="margin:16px 0 0;color:var(--text-soft);font-size:13px;">Scripts panel coming next. For now, use Open to manage this project.</p>' +
      '</div>';

    row.querySelector(".project-caret").addEventListener("click", function () {
      row.classList.toggle("is-open");
    });
    row.querySelector("[data-open]").addEventListener("click", function () {
      window.location.href = "project-view.html?id=" + p.id;
    });
    row.querySelector("[data-delete]").addEventListener("click", async function () {
      if (!window.confirm("Delete project '" + p.name + "'? This removes all scripts and keys inside it.")) return;
      try {
        const r = await window.SL.api("/api/projects/" + p.id, { method: "DELETE" });
        if (r.ok) { window.SL.toast("Project deleted", "ok"); loadAll(); }
        else window.SL.toast(r.error || "Could not delete", "error");
      } catch (e) { window.SL.toast(e.message, "error"); }
    });

    row.querySelector(".project-row-head").addEventListener("click", function (e) {
      if (e.target.closest("[data-delete]") || e.target.closest("[data-open]") || e.target.closest(".project-caret")) return;
      window.location.href = "project-view.html?id=" + p.id;
    });
    els.list.appendChild(row);
  });
}

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

// Filter tabs
els.tabs.forEach(function (tab) {
  tab.addEventListener("click", function () {
    els.tabs.forEach(function (t) { t.classList.remove("is-active"); });
    tab.classList.add("is-active");
    filter = tab.getAttribute("data-filter");
    render();
  });
});

els.search.addEventListener("input", render);
els.sort.addEventListener("change", render);

// Create modal
function openModal() {
  els.pName.value = "";
  els.pNote.value = "";
  els.createErr.classList.remove("is-visible");
  els.modal.classList.add("is-open");
  setTimeout(function () { els.pName.focus(); }, 50);
}
function closeModal() { els.modal.classList.remove("is-open"); }

els.openCreate.addEventListener("click", openModal);
els.closeCreate.addEventListener("click", closeModal);
els.cancelCreate.addEventListener("click", closeModal);
els.modal.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeModal();
});
document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeModal(); });

els.confirmCreate.addEventListener("click", async function () {
  const name = els.pName.value.trim();
  if (!name) {
    els.createErr.textContent = "Enter a project name.";
    els.createErr.classList.add("is-visible");
    return;
  }
  els.confirmCreate.disabled = true;
  els.confirmCreate.textContent = "Creating...";
  try {
    const r = await window.SL.api("/api/projects", {
      method: "POST",
      body: JSON.stringify({ name: name, note: els.pNote.value.trim() }),
    });
    if (r.ok) {
      closeModal();
      window.SL.toast("Project created", "ok");
      loadAll();
    } else {
      els.createErr.textContent = r.error || "Could not create project.";
      els.createErr.classList.add("is-visible");
    }
  } catch (e) {
    els.createErr.textContent = e.message;
    els.createErr.classList.add("is-visible");
  } finally {
    els.confirmCreate.disabled = false;
    els.confirmCreate.textContent = "Create project";
  }
});

loadAll();
