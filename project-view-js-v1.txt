// project-view.js — Solaries single project detail (Phase 2)
// Loads one project, lists its scripts, runs the 4-step New script wizard.

const params = new URLSearchParams(window.location.search);
const projectId = params.get("id");
if (!projectId) {
  window.location.replace("projects.html");
}

const el = {
  crumbName: document.getElementById("crumbName"),
  projName: document.getElementById("projName"),
  projSlug: document.getElementById("projSlug"),
  projStatusWrap: document.getElementById("projStatusWrap"),

  openWizard: document.getElementById("openWizard"),
  table: document.getElementById("scriptsTable"),
  body: document.getElementById("scriptsBody"),
  empty: document.getElementById("scriptsEmpty"),

  // Wizard modal
  wizard: document.getElementById("wizardModal"),
  closeWizard: document.getElementById("closeWizard"),
  btnCancelWiz: document.getElementById("btnCancelWiz"),
  btnBack: document.getElementById("btnBack"),
  btnNext: document.getElementById("btnNext"),
  wizardErr: document.getElementById("wizardErr"),

  steps: document.querySelectorAll(".wizard-step"),
  panels: document.querySelectorAll(".wizard-panel"),
  protectionCards: document.querySelectorAll("[data-protection]"),
  uiCards: document.querySelectorAll("[data-ui]"),

  sName: document.getElementById("sName"),
  sDesc: document.getElementById("sDesc"),
  sGame: document.getElementById("sGame"),
  sSource: document.getElementById("sSource"),
  sourceDrop: document.getElementById("sourceDrop"),
  sourceFile: document.getElementById("sourceFile"),

  tEnabled: document.getElementById("tEnabled"),
  tKeyless: document.getElementById("tKeyless"),
  tSyntax: document.getElementById("tSyntax"),
  tFast: document.getElementById("tFast"),
  tSame: document.getElementById("tSame"),
  tSilent: document.getElementById("tSilent"),

  // Loader modal
  loaderModal: document.getElementById("loaderModal"),
  loaderCode: document.getElementById("loaderCode"),
  loaderHint: document.getElementById("loaderHint"),
  loaderSubtitle: document.getElementById("loaderSubtitle"),
  closeLoader: document.getElementById("closeLoader"),
  btnCloseLoader: document.getElementById("btnCloseLoader"),
  btnCopyLoader: document.getElementById("btnCopyLoader"),
};

let project = null;
let scripts = [];
let wizard = {
  step: 1,
  protection: "none",
  ui: "no_gui",
};

// ------------------------------------------------------------
// Load
// ------------------------------------------------------------
async function loadProject() {
  try {
    // Fetch the projects list, pick the one matching id
    const r = await window.SL.api("/api/projects");
    if (!r.ok) throw new Error(r.error || "Could not load project");
    project = (r.projects || []).find(function (p) { return p.id === projectId; });
    if (!project) {
      window.SL.toast("Project not found", "error");
      setTimeout(function () { window.location.replace("projects.html"); }, 800);
      return;
    }
    renderHeader();
    loadScripts();
  } catch (e) {
    window.SL.toast(e.message, "error");
  }
}

function renderHeader() {
  el.crumbName.textContent = project.name;
  el.projName.textContent = project.name;
  el.projSlug.textContent = project.id.slice(0, 8);
  document.title = project.name + " · Solaries";
  const pill = document.createElement("span");
  pill.className = "status-pill " + (project.status === "paused" ? "is-paused" : "is-live");
  pill.textContent = project.status === "paused" ? "Paused" : "Active";
  el.projStatusWrap.innerHTML = "";
  el.projStatusWrap.appendChild(pill);
}

async function loadScripts() {
  try {
    const r = await window.SL.api("/api/projects/" + projectId + "/scripts");
    if (!r.ok) throw new Error(r.error || "Could not load scripts");
    scripts = r.scripts || [];
    renderScripts();
  } catch (e) {
    window.SL.toast(e.message, "error");
  }
}

function humanSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(2) + " MB";
}

function protectionLabel(v) {
  return { none: "None", luraph: "Luraph", wynfuscate: "wYnFuscate" }[v] || v;
}

function renderScripts() {
  el.body.innerHTML = "";
  if (scripts.length === 0) {
    el.table.style.display = "none";
    el.empty.style.display = "block";
    return;
  }
  el.table.style.display = "";
  el.empty.style.display = "none";

  scripts.forEach(function (s) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td>' +
        '<div class="cell-name">' + escapeHtml(s.name) + '</div>' +
        '<div class="cell-sub">' + escapeHtml(s.slug) + '</div>' +
      '</td>' +
      '<td>' +
        '<span class="status-pill ' + (s.enabled ? "is-live" : "is-off") + '">' + (s.enabled ? "Active" : "Disabled") + '</span>' +
        '<span class="type-pill">' + (s.key_mode === "keyless" ? "KEYLESS" : "KEYED") + '</span>' +
      '</td>' +
      '<td>' + escapeHtml(protectionLabel(s.protection)) + '</td>' +
      '<td>' + humanSize(s.size_bytes || 0) + '</td>' +
      '<td style="text-align:right">' +
        '<button class="mini-btn is-primary" data-loader>Loader</button> ' +
        '<button class="mini-btn is-danger" data-del>Delete</button>' +
      '</td>';

    tr.querySelector("[data-loader]").addEventListener("click", function () { openLoader(s); });
    tr.querySelector("[data-del]").addEventListener("click", async function () {
      if (!window.confirm("Delete script '" + s.name + "'?")) return;
      try {
        const r = await window.SL.api("/api/scripts/" + s.id, { method: "DELETE" });
        if (r.ok) { window.SL.toast("Script deleted", "ok"); loadScripts(); }
        else window.SL.toast(r.error || "Could not delete", "error");
      } catch (e) { window.SL.toast(e.message, "error"); }
    });

    el.body.appendChild(tr);
  });
}

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

// ------------------------------------------------------------
// Loader modal
// ------------------------------------------------------------
function openLoader(script) {
  const origin = window.location.origin;
  const base = origin + "/v1/load/" + script.slug;
  const line = script.key_mode === "keyless"
    ? 'loadstring(game:HttpGet("' + base + '", true))()'
    : '_G.script_key = "YOUR-KEY-HERE"\nloadstring(game:HttpGet("' + base + '?key=".._G.script_key, true))()';
  el.loaderCode.textContent = line;
  el.loaderHint.textContent = script.key_mode === "keyless"
    ? "Keyless. Anyone with this loader can run it."
    : "Replace YOUR-KEY-HERE with an active key issued for this project.";
  el.loaderSubtitle.textContent = script.name + " · " + protectionLabel(script.protection);
  el.loaderModal.classList.add("is-open");
}
function closeLoader() { el.loaderModal.classList.remove("is-open"); }
el.closeLoader.addEventListener("click", closeLoader);
el.btnCloseLoader.addEventListener("click", closeLoader);
el.loaderModal.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeLoader();
});
el.btnCopyLoader.addEventListener("click", async function () {
  try {
    await navigator.clipboard.writeText(el.loaderCode.textContent);
    window.SL.toast("Loader copied", "ok");
  } catch (e) { window.SL.toast("Copy failed", "error"); }
});

// ------------------------------------------------------------
// Wizard
// ------------------------------------------------------------
function openWizard() {
  wizard = { step: 1, protection: "none", ui: "no_gui" };
  el.sName.value = "";
  el.sDesc.value = "";
  el.sGame.value = "";
  el.sSource.value = "";
  el.tEnabled.checked = true;
  el.tKeyless.checked = false;
  el.tSyntax.checked = true;
  el.tFast.checked = false;
  el.tSame.checked = true;
  el.tSilent.checked = true;
  el.protectionCards.forEach(function (c) { c.classList.toggle("is-selected", c.dataset.protection === "none"); });
  el.uiCards.forEach(function (c) { c.classList.toggle("is-selected", c.dataset.ui === "no_gui"); });
  el.wizardErr.classList.remove("is-visible");
  showStep(1);
  el.wizard.classList.add("is-open");
}
function closeWizard() { el.wizard.classList.remove("is-open"); }

function showStep(n) {
  wizard.step = n;
  el.steps.forEach(function (s) {
    const i = parseInt(s.dataset.step, 10);
    s.classList.toggle("is-current", i === n);
    s.classList.toggle("is-done", i < n);
  });
  el.panels.forEach(function (p) {
    p.classList.toggle("is-current", parseInt(p.dataset.panel, 10) === n);
  });
  el.btnBack.style.display = n > 1 ? "" : "none";
  el.btnNext.textContent = n === 4 ? "Create script" : "Continue";
  el.wizardErr.classList.remove("is-visible");
}

// Card selection
el.protectionCards.forEach(function (c) {
  c.addEventListener("click", function () {
    el.protectionCards.forEach(function (x) { x.classList.remove("is-selected"); });
    c.classList.add("is-selected");
    wizard.protection = c.dataset.protection;
  });
});
el.uiCards.forEach(function (c) {
  c.addEventListener("click", function () {
    el.uiCards.forEach(function (x) { x.classList.remove("is-selected"); });
    c.classList.add("is-selected");
    wizard.ui = c.dataset.ui;
  });
});

// File drop / browse
el.sourceDrop.addEventListener("click", function () { el.sourceFile.click(); });
el.sourceFile.addEventListener("change", function (e) {
  const f = e.target.files[0];
  if (f) readFileInto(f);
});
["dragover", "dragenter"].forEach(function (evt) {
  el.sourceDrop.addEventListener(evt, function (e) {
    e.preventDefault();
    el.sourceDrop.classList.add("is-drag");
  });
});
["dragleave", "drop"].forEach(function (evt) {
  el.sourceDrop.addEventListener(evt, function (e) {
    e.preventDefault();
    el.sourceDrop.classList.remove("is-drag");
  });
});
el.sourceDrop.addEventListener("drop", function (e) {
  const f = e.dataTransfer.files[0];
  if (f) readFileInto(f);
});
function readFileInto(file) {
  if (file.size > 1024 * 1024) {
    window.SL.toast("File too large. Max 1 MB.", "error");
    return;
  }
  const reader = new FileReader();
  reader.onload = function () { el.sSource.value = reader.result; window.SL.toast("Loaded " + file.name, "ok"); };
  reader.readAsText(file);
}

// Navigation
el.btnBack.addEventListener("click", function () {
  if (wizard.step > 1) showStep(wizard.step - 1);
});
el.btnNext.addEventListener("click", async function () {
  // Validate current step
  if (wizard.step === 2) {
    if (!el.sName.value.trim()) {
      el.wizardErr.textContent = "Script name is required.";
      el.wizardErr.classList.add("is-visible");
      return;
    }
  }
  if (wizard.step === 4) {
    if (!el.sSource.value.trim()) {
      el.wizardErr.textContent = "Script source is required.";
      el.wizardErr.classList.add("is-visible");
      return;
    }
    return createScript();
  }
  showStep(wizard.step + 1);
});

async function createScript() {
  el.btnNext.disabled = true;
  el.btnNext.textContent = "Creating...";
  try {
    const body = {
      name: el.sName.value.trim(),
      description: el.sDesc.value.trim(),
      protection: wizard.protection,
      player_ui: wizard.ui,
      key_mode: el.tKeyless.checked ? "keyless" : "keyed",
      source: el.sSource.value,
      enabled: el.tEnabled.checked,
      syntax_check: el.tSyntax.checked,
      fast_mode: el.tFast.checked,
      same_device: el.tSame.checked,
      silent_mode: el.tSilent.checked,
      game_id: el.sGame.value.trim(),
    };
    const r = await window.SL.api("/api/projects/" + projectId + "/scripts", {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (r.ok) {
      closeWizard();
      window.SL.toast("Script created", "ok");
      loadScripts();
    } else {
      el.wizardErr.textContent = r.error || "Could not create script.";
      el.wizardErr.classList.add("is-visible");
    }
  } catch (e) {
    el.wizardErr.textContent = e.message;
    el.wizardErr.classList.add("is-visible");
  } finally {
    el.btnNext.disabled = false;
    el.btnNext.textContent = wizard.step === 4 ? "Create script" : "Continue";
  }
}

el.openWizard.addEventListener("click", openWizard);
el.closeWizard.addEventListener("click", closeWizard);
el.btnCancelWiz.addEventListener("click", closeWizard);
el.wizard.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeWizard();
});
document.addEventListener("keydown", function (e) {
  if (e.key === "Escape") { closeWizard(); closeLoader(); }
});

loadProject();
