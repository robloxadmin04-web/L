// projects.js - Solaries Projects page (mobile responsive)
// List view with stats, search, sort, filter tabs, and create modal.
// Pure ASCII only - no special characters.

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

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
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
  if (filter === "shared") list = [];

  if (term) {
    list = list.filter(function (p) {
      return p.name.toLowerCase().includes(term)
        || (p.note || "").toLowerCase().includes(term)
        || p.slug.toLowerCase().includes(term);
    });
  }

  if (sortMode === "name") list.sort(function (a, b) { return a.name.localeCompare(b.name); });
  else if (sortMode === "scripts") list.sort(function (a, b) { return (b.script_count || 0) - (a.script_count || 0); });
  else list.sort(function (a, b) { return new Date(b.created_at) - new Date(a.created_at); });

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
    const card = document.createElement("div");
    card.className = "proj-card";
    const scriptCount = p.script_count || 0;
    const keyCount = p.key_count || 0;
    const statusClass = p.status === "paused" ? "is-paused" : "is-live";
    const statusText = p.status === "paused" ? "Paused" : "Active";

    card.innerHTML =
      '<div class="proj-card-head">' +
        '<span class="proj-caret"><svg viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"></path></svg></span>' +
        '<span class="proj-icon"><svg viewBox="0 0 24 24"><path d="M3 7h7l2 2h9v10a1 1 0 01-1 1H4a1 1 0 01-1-1V7z"></path></svg></span>' +
        '<div class="proj-info">' +
          '<div class="proj-title-row">' +
            '<span class="proj-title">' + escapeHtml(p.name) + '</span>' +
            '<span class="status-pill ' + statusClass + '">' + statusText + '</span>' +
          '</div>' +
          '<div class="proj-sub">' +
            '<code>' + escapeHtml(shortId(p.id)) + '</code>' +
            '<span class="dot">-</span>' +
            '<span>' + scriptCount + ' ' + (scriptCount === 1 ? 'script' : 'scripts') + '</span>' +
            '<span class="dot">-</span>' +
            '<span>' + keyCount + ' ' + (keyCount === 1 ? 'key' : 'keys') + '</span>' +
          '</div>' +
        '</div>' +
        '<div class="proj-actions">' +
          '<button class="mini-btn is-primary" data-open type="button">Open</button>' +
          '<button class="mini-btn is-danger" data-delete type="button">Delete</button>' +
        '</div>' +
      '</div>' +
      '<div class="proj-card-body">' +
        (p.note
          ? '<p style="margin:0;color:var(--text-soft);font-size:13px;line-height:1.5">' + escapeHtml(p.note) + '</p>'
          : '<p style="margin:0;color:var(--text-muted);font-size:13px;font-style:italic">No description yet.</p>'
        ) +
      '</div>';

    const caret = card.querySelector(".proj-caret");
    caret.addEventListener("click", function (e) {
      e.stopPropagation();
      card.classList.toggle("is-open");
    });

    card.querySelector("[data-open]").addEventListener("click", function (e) {
      e.stopPropagation();
      window.location.href = "project-view.html?id=" + p.id;
    });

    card.querySelector("[data-delete]").addEventListener("click", async function (e) {
      e.stopPropagation();
      if (!window.confirm("Delete project '" + p.name + "'? This removes all scripts and keys inside it.")) return;
      try {
        const r = await window.SL.api("/api/projects/" + p.id, { method: "DELETE" });
        if (r.ok) { window.SL.toast("Project deleted", "ok"); loadAll(); }
        else window.SL.toast(r.error || "Could not delete", "error");
      } catch (err) { window.SL.toast(err.message, "error"); }
    });

    els.list.appendChild(card);
  });
}

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
