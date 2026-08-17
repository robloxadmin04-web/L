// project-view.js - Solaries Project detail (Phase 6 D2 UI)
// Adds: Discord panel modal per script with copy-to-clipboard command
// Also has: edit script, version history + restore, blocklist, allowlist,
// whitelist-only toggle, pause/resume, rename, delete project.

const params = new URLSearchParams(window.location.search);
const projectId = params.get("id");
if (!projectId) window.location.replace("projects.html");

const el = {
  crumbName: document.getElementById("crumbName"),
  projName: document.getElementById("projName"),
  projSlug: document.getElementById("projSlug"),
  projStatusWrap: document.getElementById("projStatusWrap"),

  btnRename: document.getElementById("btnRename"),
  btnPause: document.getElementById("btnPause"),
  btnDelete: document.getElementById("btnDelete"),
  tWhitelist: document.getElementById("tWhitelist"),

  openWizard: document.getElementById("openWizard"),
  wizardTitle: document.getElementById("wizardTitle"),
  table: document.getElementById("scriptsTable"),
  body: document.getElementById("scriptsBody"),
  empty: document.getElementById("scriptsEmpty"),

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
  sSlug: document.getElementById("sSlug"),
  slugField: document.getElementById("slugField"),
  btnAutoSlug: document.getElementById("btnAutoSlug"),
  sSlugPreview: document.getElementById("sSlugPreview"),
  sGame: document.getElementById("sGame"),
  sSource: document.getElementById("sSource"),
  sVersionNote: document.getElementById("sVersionNote"),
  versionNoteField: document.getElementById("versionNoteField"),
  sourceDrop: document.getElementById("sourceDrop"),
  sourceFile: document.getElementById("sourceFile"),

  tEnabled: document.getElementById("tEnabled"),
  tKeyless: document.getElementById("tKeyless"),
  tSyntax: document.getElementById("tSyntax"),
  tFast: document.getElementById("tFast"),
  tSame: document.getElementById("tSame"),
  tSilent: document.getElementById("tSilent"),

  loaderModal: document.getElementById("loaderModal"),
  loaderCode: document.getElementById("loaderCode"),
  loaderHint: document.getElementById("loaderHint"),
  loaderSubtitle: document.getElementById("loaderSubtitle"),
  closeLoader: document.getElementById("closeLoader"),
  btnCloseLoader: document.getElementById("btnCloseLoader"),
  btnCopyLoader: document.getElementById("btnCopyLoader"),

  discordModal: document.getElementById("discordModal"),
  discordSubtitle: document.getElementById("discordSubtitle"),
  discordCmd: document.getElementById("discordCmd"),
  discordInvite: document.getElementById("discordInvite"),
  closeDiscord: document.getElementById("closeDiscord"),
  btnCloseDiscord: document.getElementById("btnCloseDiscord"),
  btnCopyDiscord: document.getElementById("btnCopyDiscord"),
  btnCopyInvite: document.getElementById("btnCopyInvite"),

  historyModal: document.getElementById("historyModal"),
  historySubtitle: document.getElementById("historySubtitle"),
  historyList: document.getElementById("historyList"),
  historyEmpty: document.getElementById("historyEmpty"),
  closeHistory: document.getElementById("closeHistory"),
  btnCloseHistory: document.getElementById("btnCloseHistory"),

  blockBody: document.getElementById("blockBody"),
  blockEmpty: document.getElementById("blockEmpty"),
  blType: document.getElementById("blType"),
  blValue: document.getElementById("blValue"),
  blReason: document.getElementById("blReason"),
  btnAddBlock: document.getElementById("btnAddBlock"),

  allowBody: document.getElementById("allowBody"),
  allowEmpty: document.getElementById("allowEmpty"),
  alType: document.getElementById("alType"),
  alValue: document.getElementById("alValue"),
  alNote: document.getElementById("alNote"),
  btnAddAllow: document.getElementById("btnAddAllow"),
};

let project = null;
let scripts = [];
let editingScript = null;
let wizard = { step: 1, protection: "none", ui: "no_gui" };

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}
function humanSize(b) {
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  return (b / 1048576).toFixed(2) + " MB";
}
function protectionLabel(v) { return { none: "None", luraph: "Luraph", wynfuscate: "wYnFuscate" }[v] || v; }
function slugify(text) {
  return String(text || "").toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-")
    .slice(0, 40);
}
function isValidSlug(s) {
  if (!s) return true; // empty is allowed (auto-generate)
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(s) && s.length >= 3 && s.length <= 40;
}
function updateSlugPreview() {
  if (!el.sSlugPreview || !el.sSlug) return;
  const val = el.sSlug.value.trim().toLowerCase();
  if (!val) {
    el.sSlugPreview.textContent = "Auto: " + (el.sName.value.trim() ? slugify(el.sName.value) + "-xxxx" : "based on name");
    el.sSlugPreview.style.color = "var(--text-muted)";
  } else if (!isValidSlug(val)) {
    el.sSlugPreview.textContent = "Invalid: must be 3-40 chars, a-z 0-9 dash only";
    el.sSlugPreview.style.color = "#fca5a5";
  } else {
    el.sSlugPreview.textContent = "URL: /v1/load/" + val;
    el.sSlugPreview.style.color = "var(--text-muted)";
  }
}
function formatDate(v) {
  if (!v) return "-";
  const d = new Date(v);
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
}

async function loadProject() {
  try {
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
    loadBlocklist();
    loadAllowlist();
  } catch (e) { window.SL.toast(e.message, "error"); }
}

function renderHeader() {
  el.crumbName.textContent = project.name;
  el.projName.textContent = project.name;
  el.projSlug.textContent = project.id.slice(0, 8);
  document.title = project.name + " - Solaries";
  const pill = document.createElement("span");
  pill.className = "status-pill " + (project.status === "paused" ? "is-paused" : "is-live");
  pill.textContent = project.status === "paused" ? "Paused" : "Active";
  el.projStatusWrap.innerHTML = "";
  el.projStatusWrap.appendChild(pill);
  el.btnPause.textContent = project.status === "paused" ? "Resume" : "Pause";
  el.tWhitelist.checked = !!project.whitelist_only;
}

async function loadScripts() {
  try {
    const r = await window.SL.api("/api/projects/" + projectId + "/scripts");
    if (!r.ok) throw new Error(r.error || "Could not load scripts");
    scripts = r.scripts || [];
    renderScripts();
  } catch (e) { window.SL.toast(e.message, "error"); }
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
      '<td data-label="Script">' +
        '<div class="cell-name">' + escapeHtml(s.name) + '</div>' +
        '<div class="cell-sub">' + escapeHtml(s.slug) + '</div>' +
      '</td>' +
      '<td data-label="Status">' +
        '<span class="status-pill ' + (s.enabled ? "is-live" : "is-off") + '">' + (s.enabled ? "Active" : "Disabled") + '</span>' +
        '<span class="type-pill">' + (s.key_mode === "keyless" ? "KEYLESS" : "KEYED") + '</span>' +
      '</td>' +
      '<td data-label="Protection">' + escapeHtml(protectionLabel(s.protection)) + '</td>' +
      '<td data-label="Version" style="color:var(--text-soft)">v' + (s.version || 1) + '</td>' +
      '<td data-label="Size">' + humanSize(s.size_bytes || 0) + '</td>' +
      '<td data-label="Actions" style="text-align:right">' +
        '<button class="mini-btn is-primary" data-loader>Loader</button> ' +
        '<button class="mini-btn" data-discord>Discord</button> ' +
        '<button class="mini-btn" data-edit>Edit</button> ' +
        '<button class="mini-btn" data-history>History</button> ' +
        '<button class="mini-btn is-danger" data-del>Delete</button>' +
      '</td>';

    tr.querySelector("[data-loader]").addEventListener("click", function () { openLoader(s); });
    tr.querySelector("[data-discord]").addEventListener("click", function () { openDiscord(s); });
    tr.querySelector("[data-edit]").addEventListener("click", function () { openWizardForEdit(s); });
    tr.querySelector("[data-history]").addEventListener("click", function () { openHistory(s); });
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

// ------------------------------------------------------------
// Loader modal
// ------------------------------------------------------------
function buildHandshakeLoader(loaderUrl, extraQueryLua) {
  // Mirrors server.js's buildHandshakeLoader exactly, so the website loader
  // and the Discord-bot loader are always byte-for-byte the same shape:
  // handshake first (to get "c"), then load with px/gp/c(/key).
  const origin = window.location.origin;
  return [
    'local _z9 = tostring(game:GetService("Players").LocalPlayer.UserId)',
    'local _gp = tostring(game.PlaceId)',
    'local _c = ""',
    'local _hsOk, _hsBody = pcall(function() return game:HttpGet("' + origin + '/v1/handshake?px=".._z9.."&gp=".._gp) end)',
    'if _hsOk and _hsBody then _c = tostring(_hsBody) end',
    'loadstring(game:HttpGet("' + loaderUrl + '?px=".._z9.."&gp=".._gp' + (extraQueryLua ? '..' + extraQueryLua : '') + '.."&c=".._c))()',
  ].join("\n");
}

function openLoader(script) {
  const origin = window.location.origin;
  const base = origin + "/v1/load/" + script.slug;
  const line = script.key_mode === "keyless"
    ? buildHandshakeLoader(base, "")
    : '_G.script_key = "YOUR-KEY-HERE"\n' + buildHandshakeLoader(base, '"&key=".._G.script_key');
  el.loaderCode.textContent = line;
  el.loaderHint.textContent = script.key_mode === "keyless"
    ? "Keyless. Anyone with this loader can run it."
    : "Replace YOUR-KEY-HERE with an active key issued for this project.";
  el.loaderSubtitle.textContent = script.name + " - " + protectionLabel(script.protection);
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
// Discord panel modal
// ------------------------------------------------------------
function openDiscord(script) {
  el.discordSubtitle.textContent = script.name + " - slug: " + script.slug;
  el.discordCmd.textContent = "/panel script_id:" + script.slug;
  el.discordModal.classList.add("is-open");
}
function closeDiscord() { el.discordModal.classList.remove("is-open"); }
el.closeDiscord.addEventListener("click", closeDiscord);
el.btnCloseDiscord.addEventListener("click", closeDiscord);
el.discordModal.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeDiscord();
});
el.btnCopyDiscord.addEventListener("click", async function () {
  try {
    await navigator.clipboard.writeText(el.discordCmd.textContent);
    window.SL.toast("Command copied", "ok");
  } catch (e) { window.SL.toast("Copy failed", "error"); }
});
el.btnCopyInvite.addEventListener("click", async function () {
  try {
    await navigator.clipboard.writeText(el.discordInvite.textContent);
    window.SL.toast("Invite link copied", "ok");
  } catch (e) { window.SL.toast("Copy failed", "error"); }
});

// ------------------------------------------------------------
// Wizard (create or edit)
// ------------------------------------------------------------
function openWizardForCreate() {
  editingScript = null;
  el.wizardTitle.textContent = "New script";
  wizard = { step: 1, protection: "none", ui: "no_gui" };
  el.sName.value = "";
  el.sDesc.value = "";
  el.sGame.value = "";
  if (el.sSlug) el.sSlug.value = "";
  if (el.slugField) el.slugField.style.display = "";
  updateSlugPreview();
  el.sSource.value = "";
  el.sVersionNote.value = "";
  el.versionNoteField.style.display = "none";
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

async function openWizardForEdit(s) {
  try {
    const r = await window.SL.api("/api/scripts/" + s.id + "/versions");
    editingScript = s;
    el.wizardTitle.textContent = "Edit " + s.name;
    wizard = { step: 1, protection: s.protection || "none", ui: s.player_ui || "no_gui" };

    if (r.ok && r.versions && r.versions.length > 0) {
      const latest = r.versions[0];
      const vr = await window.SL.api("/api/scripts/" + s.id + "/versions/" + latest.version);
      el.sSource.value = vr.ok && vr.version ? vr.version.source : "";
    } else {
      el.sSource.value = "";
    }

    el.sName.value = s.name || "";
    el.sDesc.value = s.description || "";
    el.sGame.value = s.game_id || "";
    if (el.slugField) el.slugField.style.display = "none";
    el.sVersionNote.value = "";
    el.versionNoteField.style.display = "block";
    el.tEnabled.checked = s.enabled !== false;
    el.tKeyless.checked = s.key_mode === "keyless";
    el.tSyntax.checked = s.syntax_check !== false;
    el.tFast.checked = !!s.fast_mode;
    el.tSame.checked = s.same_device !== false;
    el.tSilent.checked = s.silent_mode !== false;
    el.protectionCards.forEach(function (c) { c.classList.toggle("is-selected", c.dataset.protection === wizard.protection); });
    el.uiCards.forEach(function (c) { c.classList.toggle("is-selected", c.dataset.ui === wizard.ui); });
    el.wizardErr.classList.remove("is-visible");
    showStep(1);
    el.wizard.classList.add("is-open");
  } catch (e) { window.SL.toast(e.message, "error"); }
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
  el.btnNext.textContent = n === 4 ? (editingScript ? "Save changes" : "Create script") : "Continue";
  el.wizardErr.classList.remove("is-visible");
}

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

if (el.sSlug) {
  el.sSlug.addEventListener("input", function () {
    // Auto-lowercase + strip invalid chars as user types
    const cleaned = el.sSlug.value.toLowerCase().replace(/[^a-z0-9-]/g, "");
    if (cleaned !== el.sSlug.value) el.sSlug.value = cleaned;
    updateSlugPreview();
  });
}
if (el.btnAutoSlug) {
  el.btnAutoSlug.addEventListener("click", function () {
    const base = slugify(el.sName.value) || "script";
    const suffix = Math.random().toString(36).slice(2, 6);
    el.sSlug.value = (base + "-" + suffix).slice(0, 40);
    updateSlugPreview();
  });
}
if (el.sName) {
  el.sName.addEventListener("input", updateSlugPreview);
}
if (el.sGame) {
  // PlaceIds are numeric only - strip anything else as the user types,
  // same pattern as the slug field's live cleanup.
  el.sGame.addEventListener("input", function () {
    const cleaned = el.sGame.value.replace(/[^0-9]/g, "");
    if (cleaned !== el.sGame.value) el.sGame.value = cleaned;
  });
}
function isValidGameId(v) {
  return v === "" || /^\d{1,20}$/.test(v);
}

el.sourceDrop.addEventListener("click", function () { el.sourceFile.click(); });
el.sourceFile.addEventListener("change", function (e) {
  const f = e.target.files[0];
  if (f) readFileInto(f);
});
["dragover", "dragenter"].forEach(function (evt) {
  el.sourceDrop.addEventListener(evt, function (e) { e.preventDefault(); el.sourceDrop.classList.add("is-drag"); });
});
["dragleave", "drop"].forEach(function (evt) {
  el.sourceDrop.addEventListener(evt, function (e) { e.preventDefault(); el.sourceDrop.classList.remove("is-drag"); });
});
el.sourceDrop.addEventListener("drop", function (e) {
  const f = e.dataTransfer.files[0];
  if (f) readFileInto(f);
});
function readFileInto(file) {
  if (file.size > 10485760) { window.SL.toast("File too large. Max 10 MB.", "error"); return; }
  const reader = new FileReader();
  reader.onload = function () { el.sSource.value = reader.result; window.SL.toast("Loaded " + file.name, "ok"); };
  reader.readAsText(file);
}

el.btnBack.addEventListener("click", function () { if (wizard.step > 1) showStep(wizard.step - 1); });

el.btnNext.addEventListener("click", async function () {
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
    return editingScript ? updateScript() : createScript();
  }
  showStep(wizard.step + 1);
});

async function createScript() {
  el.btnNext.disabled = true;
  el.btnNext.textContent = "Creating...";
  const customSlug = el.sSlug ? el.sSlug.value.trim().toLowerCase() : "";
  if (customSlug && !isValidSlug(customSlug)) {
    el.wizardErr.textContent = "Custom slug is invalid. Must be 3-40 chars: lowercase a-z, 0-9, and dashes only.";
    el.wizardErr.classList.add("is-visible");
    el.btnNext.disabled = false;
    el.btnNext.textContent = "Create script";
    return;
  }
  if (!isValidGameId(el.sGame.value.trim())) {
    el.wizardErr.textContent = "Game ID must be a numeric Roblox PlaceId (or left blank).";
    el.wizardErr.classList.add("is-visible");
    el.btnNext.disabled = false;
    el.btnNext.textContent = "Create script";
    return;
  }
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
    if (customSlug) body.slug = customSlug;
    const r = await window.SL.api("/api/projects/" + projectId + "/scripts", {
      method: "POST", body: JSON.stringify(body),
    });
    if (r.ok) { closeWizard(); window.SL.toast("Script created", "ok"); loadScripts(); }
    else { el.wizardErr.textContent = r.error || "Could not create script."; el.wizardErr.classList.add("is-visible"); }
  } catch (e) { el.wizardErr.textContent = e.message; el.wizardErr.classList.add("is-visible"); }
  finally { el.btnNext.disabled = false; el.btnNext.textContent = "Create script"; }
}

async function updateScript() {
  el.btnNext.disabled = true;
  el.btnNext.textContent = "Saving...";
  if (!isValidGameId(el.sGame.value.trim())) {
    el.wizardErr.textContent = "Game ID must be a numeric Roblox PlaceId (or left blank).";
    el.wizardErr.classList.add("is-visible");
    el.btnNext.disabled = false;
    el.btnNext.textContent = "Save changes";
    return;
  }
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
      version_note: el.sVersionNote.value.trim() || null,
    };
    const r = await window.SL.api("/api/scripts/" + editingScript.id, {
      method: "PATCH", body: JSON.stringify(body),
    });
    if (r.ok) { closeWizard(); window.SL.toast("Script saved", "ok"); loadScripts(); }
    else { el.wizardErr.textContent = r.error || "Could not save script."; el.wizardErr.classList.add("is-visible"); }
  } catch (e) { el.wizardErr.textContent = e.message; el.wizardErr.classList.add("is-visible"); }
  finally { el.btnNext.disabled = false; el.btnNext.textContent = "Save changes"; }
}

el.openWizard.addEventListener("click", openWizardForCreate);
el.closeWizard.addEventListener("click", closeWizard);
el.btnCancelWiz.addEventListener("click", closeWizard);
el.wizard.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeWizard();
});

// ------------------------------------------------------------
// Version history
// ------------------------------------------------------------
async function openHistory(s) {
  el.historySubtitle.textContent = s.name;
  el.historyList.innerHTML = "";
  el.historyEmpty.style.display = "none";
  el.historyModal.classList.add("is-open");
  try {
    const r = await window.SL.api("/api/scripts/" + s.id + "/versions");
    if (!r.ok) throw new Error(r.error || "Could not load history");
    const versions = r.versions || [];
    if (versions.length === 0) { el.historyEmpty.style.display = "block"; return; }
    versions.forEach(function (v) {
      const item = document.createElement("div");
      item.className = "version-item";
      const isCurrent = v.version === s.version;
      item.innerHTML =
        '<div>' +
          '<span class="version-num">v' + v.version + '</span>' +
          (isCurrent ? ' <span class="status-pill is-live" style="margin-left:6px">Current</span>' : '') +
          '<div class="version-meta">' + humanSize(v.size_bytes || 0) + ' - ' + formatDate(v.created_at) + (v.note ? ' - ' + escapeHtml(v.note) : '') + '</div>' +
        '</div>' +
        '<div style="display:flex;gap:6px">' +
          (isCurrent ? '' : '<button class="mini-btn is-primary" data-restore="' + v.version + '">Restore</button>') +
        '</div>';
      const restoreBtn = item.querySelector("[data-restore]");
      if (restoreBtn) {
        restoreBtn.addEventListener("click", async function () {
          if (!window.confirm("Restore v" + v.version + "? A new version will be created with this content.")) return;
          try {
            const rr = await window.SL.api("/api/scripts/" + s.id + "/restore/" + v.version, { method: "POST" });
            if (rr.ok) { window.SL.toast("Restored to v" + v.version, "ok"); closeHistory(); loadScripts(); }
            else window.SL.toast(rr.error || "Could not restore", "error");
          } catch (e) { window.SL.toast(e.message, "error"); }
        });
      }
      el.historyList.appendChild(item);
    });
  } catch (e) { window.SL.toast(e.message, "error"); }
}
function closeHistory() { el.historyModal.classList.remove("is-open"); }
el.closeHistory.addEventListener("click", closeHistory);
el.btnCloseHistory.addEventListener("click", closeHistory);
el.historyModal.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeHistory();
});

// ------------------------------------------------------------
// Whitelist toggle, Pause, Rename, Delete
// ------------------------------------------------------------
el.tWhitelist.addEventListener("change", async function () {
  try {
    const r = await window.SL.api("/api/projects/" + projectId, {
      method: "PATCH", body: JSON.stringify({ whitelist_only: el.tWhitelist.checked }),
    });
    if (r.ok) { project = r.project; window.SL.toast("Whitelist mode " + (el.tWhitelist.checked ? "on" : "off"), "ok"); }
    else { el.tWhitelist.checked = !el.tWhitelist.checked; window.SL.toast(r.error || "Could not update", "error"); }
  } catch (e) { el.tWhitelist.checked = !el.tWhitelist.checked; window.SL.toast(e.message, "error"); }
});

el.btnPause.addEventListener("click", async function () {
  const newStatus = project.status === "paused" ? "active" : "paused";
  try {
    const r = await window.SL.api("/api/projects/" + projectId, {
      method: "PATCH", body: JSON.stringify({ status: newStatus }),
    });
    if (r.ok) { project = r.project; renderHeader(); window.SL.toast("Project " + newStatus, "ok"); }
    else window.SL.toast(r.error || "Could not update", "error");
  } catch (e) { window.SL.toast(e.message, "error"); }
});

el.btnRename.addEventListener("click", async function () {
  const newName = window.prompt("New project name:", project.name);
  if (!newName || newName.trim() === project.name) return;
  try {
    const r = await window.SL.api("/api/projects/" + projectId, {
      method: "PATCH", body: JSON.stringify({ name: newName.trim() }),
    });
    if (r.ok) { project = r.project; renderHeader(); window.SL.toast("Renamed", "ok"); }
    else window.SL.toast(r.error || "Could not rename", "error");
  } catch (e) { window.SL.toast(e.message, "error"); }
});

el.btnDelete.addEventListener("click", async function () {
  if (!window.confirm("Delete project '" + project.name + "'? This removes all scripts, keys, blocklist, and allowlist tied to it.")) return;
  try {
    const r = await window.SL.api("/api/projects/" + projectId, { method: "DELETE" });
    if (r.ok) { window.SL.toast("Project deleted", "ok"); setTimeout(function () { window.location.href = "projects.html"; }, 500); }
    else window.SL.toast(r.error || "Could not delete", "error");
  } catch (e) { window.SL.toast(e.message, "error"); }
});

// ------------------------------------------------------------
// Blocklist
// ------------------------------------------------------------
async function loadBlocklist() {
  try {
    const r = await window.SL.api("/api/projects/" + projectId + "/blocklist");
    if (!r.ok) return;
    renderBlocklist(r.entries || []);
  } catch (e) {}
}
function renderBlocklist(entries) {
  el.blockBody.innerHTML = "";
  if (entries.length === 0) { el.blockEmpty.style.display = "block"; return; }
  el.blockEmpty.style.display = "none";
  entries.forEach(function (e) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td data-label="Type"><span class="type-pill">' + e.entry_type.toUpperCase() + '</span></td>' +
      '<td data-label="Value"><span class="key-code" style="font-family:Consolas,Monaco,monospace;font-size:12px;color:var(--white)">' + escapeHtml(e.value) + '</span></td>' +
      '<td data-label="Reason" style="color:var(--text-soft)">' + escapeHtml(e.reason || "-") + '</td>' +
      '<td data-label="Added" style="color:var(--text-soft)">' + formatDate(e.created_at) + '</td>' +
      '<td data-label="Actions" style="text-align:right"><button class="mini-btn is-danger" data-del>Remove</button></td>';
    tr.querySelector("[data-del]").addEventListener("click", async function () {
      if (!window.confirm("Remove this block entry?")) return;
      try {
        const r = await window.SL.api("/api/blocklist/" + e.id, { method: "DELETE" });
        if (r.ok) { window.SL.toast("Removed", "ok"); loadBlocklist(); }
        else window.SL.toast(r.error || "Could not remove", "error");
      } catch (err) { window.SL.toast(err.message, "error"); }
    });
    el.blockBody.appendChild(tr);
  });
}
el.btnAddBlock.addEventListener("click", async function () {
  const value = el.blValue.value.trim();
  if (!value) { window.SL.toast("Value is required", "error"); return; }
  try {
    const r = await window.SL.api("/api/projects/" + projectId + "/blocklist", {
      method: "POST",
      body: JSON.stringify({ entry_type: el.blType.value, value: value, reason: el.blReason.value.trim() }),
    });
    if (r.ok) {
      el.blValue.value = ""; el.blReason.value = "";
      window.SL.toast("Blocked", "ok"); loadBlocklist();
    } else window.SL.toast(r.error || "Could not add", "error");
  } catch (e) { window.SL.toast(e.message, "error"); }
});

// ------------------------------------------------------------
// Allowlist
// ------------------------------------------------------------
async function loadAllowlist() {
  try {
    const r = await window.SL.api("/api/projects/" + projectId + "/allowlist");
    if (!r.ok) return;
    renderAllowlist(r.entries || []);
  } catch (e) {}
}
function renderAllowlist(entries) {
  el.allowBody.innerHTML = "";
  if (entries.length === 0) { el.allowEmpty.style.display = "block"; return; }
  el.allowEmpty.style.display = "none";
  entries.forEach(function (e) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td data-label="Type"><span class="type-pill">' + e.entry_type.toUpperCase() + '</span></td>' +
      '<td data-label="Value"><span style="font-family:Consolas,Monaco,monospace;font-size:12px;color:var(--white)">' + escapeHtml(e.value) + '</span></td>' +
      '<td data-label="Note" style="color:var(--text-soft)">' + escapeHtml(e.note || "-") + '</td>' +
      '<td data-label="Added" style="color:var(--text-soft)">' + formatDate(e.created_at) + '</td>' +
      '<td data-label="Actions" style="text-align:right"><button class="mini-btn is-danger" data-del>Remove</button></td>';
    tr.querySelector("[data-del]").addEventListener("click", async function () {
      if (!window.confirm("Remove this allow entry?")) return;
      try {
        const r = await window.SL.api("/api/allowlist/" + e.id, { method: "DELETE" });
        if (r.ok) { window.SL.toast("Removed", "ok"); loadAllowlist(); }
        else window.SL.toast(r.error || "Could not remove", "error");
      } catch (err) { window.SL.toast(err.message, "error"); }
    });
    el.allowBody.appendChild(tr);
  });
}
el.btnAddAllow.addEventListener("click", async function () {
  const value = el.alValue.value.trim();
  if (!value) { window.SL.toast("Value is required", "error"); return; }
  try {
    const r = await window.SL.api("/api/projects/" + projectId + "/allowlist", {
      method: "POST",
      body: JSON.stringify({ entry_type: el.alType.value, value: value, note: el.alNote.value.trim() }),
    });
    if (r.ok) {
      el.alValue.value = ""; el.alNote.value = "";
      window.SL.toast("Allowed", "ok"); loadAllowlist();
    } else window.SL.toast(r.error || "Could not add", "error");
  } catch (e) { window.SL.toast(e.message, "error"); }
});

document.addEventListener("keydown", function (e) {
  if (e.key === "Escape") { closeWizard(); closeLoader(); closeHistory(); closeDiscord(); }
});

loadProject();
