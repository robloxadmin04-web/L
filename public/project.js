// project.js â€” with visible error messages inside the modal
// Owner projects page. Talks to the backend with the owner token.

const API_BASE = "";
const TOKEN_KEY = "kf_owner_token";

const els = {
  list: document.getElementById("projectsList"),
  empty: document.getElementById("projectsEmpty"),
  detail: document.getElementById("projectDetail"),
  detailName: document.getElementById("detailName"),
  loaderLine: document.getElementById("loaderLine"),
  loaderHint: document.getElementById("loaderHint"),
  copyLoader: document.getElementById("copyLoader"),
  keyModeSelect: document.getElementById("keyModeSelect"),
  scriptInput: document.getElementById("scriptInput"),
  saveProject: document.getElementById("saveProject"),
  saveStatus: document.getElementById("saveStatus"),
  deleteProject: document.getElementById("deleteProject"),
  openCreate: document.getElementById("openCreate"),
  modal: document.getElementById("createModal"),
  closeModal: document.getElementById("closeModal"),
  cancelModal: document.getElementById("cancelModal"),
  confirmCreate: document.getElementById("confirmCreate"),
  nameInput: document.getElementById("nameInput"),
  modeInput: document.getElementById("modeInput"),
  menuToggle: document.getElementById("menuToggle"),
  sidebar: document.getElementById("sidebar"),
  themeToggle: document.getElementById("themeToggle"),
};

let projects = [];
let current = null;
let modalStatus = null;

function ensureModalStatus() {
  if (modalStatus) return modalStatus;
  const body = els.modal.querySelector(".modal-body");
  modalStatus = document.createElement("p");
  modalStatus.style.cssText = "margin:0;padding:10px 12px;border-radius:10px;font-size:13px;display:none;";
  body.appendChild(modalStatus);
  return modalStatus;
}

function showModalError(text) {
  const s = ensureModalStatus();
  s.textContent = text;
  s.style.background = "#2a1416";
  s.style.color = "#fca5a5";
  s.style.border = "1px solid #4a1e22";
  s.style.display = "block";
}

function hideModalError() {
  const s = ensureModalStatus();
  s.style.display = "none";
}

function getToken() {
  let token = sessionStorage.getItem(TOKEN_KEY);
  if (!token) {
    token = window.prompt("Enter owner token");
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token.trim());
    }
  }
  return sessionStorage.getItem(TOKEN_KEY);
}

function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

async function api(pathName, options) {
  const token = getToken();
  const config = options || {};
  config.headers = Object.assign(
    { "Content-Type": "application/json", "x-owner-token": token || "" },
    config.headers || {}
  );
  const response = await fetch(API_BASE + pathName, config);
  if (response.status === 401) {
    clearToken();
    throw new Error("Unauthorized. Wrong owner token.");
  }
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error("Server returned: " + text.slice(0, 120));
  }
}

function loaderFor(project) {
  const base = window.location.origin;
  if (project.key_mode === "keyed") {
    return 'loadstring(game:HttpGet("' + base + "/v1/load/" + project.slug + '?key=YOUR_KEY", true))()';
  }
  return 'loadstring(game:HttpGet("' + base + "/v1/load/" + project.slug + '", true))()';
}

async function loadProjects() {
  try {
    const result = await api("/api/projects", { method: "GET" });
    if (result.ok) {
      projects = result.projects || [];
      renderList();
    } else {
      window.alert(result.error || "Could not load projects");
    }
  } catch (error) {
    window.alert(error.message);
  }
}

function renderList() {
  els.list.innerHTML = "";
  projects.forEach(function (p) {
    const item = document.createElement("div");
    item.className = "project-item" + (current && current.id === p.id ? " is-active" : "");

    const main = document.createElement("div");
    main.className = "project-item-main";
    const name = document.createElement("p");
    name.className = "project-item-name";
    name.textContent = p.name;
    const slug = document.createElement("p");
    slug.className = "project-item-slug";
    slug.textContent = p.slug;
    main.appendChild(name);
    main.appendChild(slug);

    const pill = document.createElement("span");
    pill.className = "mode-pill " + (p.key_mode === "keyed" ? "is-keyed" : "");
    pill.textContent = p.key_mode === "keyed" ? "Keyed" : "Keyless";

    item.appendChild(main);
    item.appendChild(pill);
    item.addEventListener("click", function () { openProject(p.id); });
    els.list.appendChild(item);
  });

  const hasRows = projects.length > 0;
  els.empty.style.display = hasRows ? "none" : "block";
}

async function openProject(id) {
  try {
    const result = await api("/api/projects/" + id, { method: "GET" });
    if (!result.ok) return;
    current = result.project;
    els.detail.style.display = "block";
    els.detailName.textContent = current.name;
    els.loaderLine.textContent = loaderFor(current);
    els.loaderHint.textContent = current.key_mode === "keyed"
      ? "Replace YOUR_KEY with an active API key before sharing."
      : "Keyless project. Anyone with this line can load it.";
    els.keyModeSelect.value = current.key_mode;
    els.scriptInput.value = current.script || "";
    els.saveStatus.textContent = "";
    renderList();
  } catch (error) {
    window.alert(error.message);
  }
}

async function saveProject() {
  if (!current) return;
  try {
    const result = await api("/api/projects/" + current.id, {
      method: "PATCH",
      body: JSON.stringify({ script: els.scriptInput.value, key_mode: els.keyModeSelect.value }),
    });
    if (result.ok) {
      current = result.project;
      els.loaderLine.textContent = loaderFor(current);
      els.loaderHint.textContent = current.key_mode === "keyed"
        ? "Replace YOUR_KEY with an active API key before sharing."
        : "Keyless project. Anyone with this line can load it.";
      els.saveStatus.textContent = "Saved";
      els.saveStatus.className = "save-status is-ok";
      setTimeout(function () {
        els.saveStatus.textContent = "";
        els.saveStatus.className = "save-status";
      }, 1600);
      loadProjects();
    } else {
      window.alert(result.error || "Could not save");
    }
  } catch (error) {
    window.alert(error.message);
  }
}

async function deleteProject() {
  if (!current) return;
  if (!window.confirm("Delete this project permanently?")) return;
  try {
    const result = await api("/api/projects/" + current.id, { method: "DELETE" });
    if (result.ok) {
      current = null;
      els.detail.style.display = "none";
      loadProjects();
    } else {
      window.alert(result.error || "Could not delete");
    }
  } catch (error) {
    window.alert(error.message);
  }
}

async function createProject() {
  hideModalError();
  const name = els.nameInput.value.trim();
  if (!name) {
    showModalError("Enter a project name.");
    return;
  }

  els.confirmCreate.disabled = true;
  const originalText = els.confirmCreate.textContent;
  els.confirmCreate.textContent = "Creating...";

  try {
    const result = await api("/api/projects", {
      method: "POST",
      body: JSON.stringify({ name: name, key_mode: els.modeInput.value }),
    });

    if (result.ok) {
      closeModal();
      await loadProjects();
      openProject(result.project.id);
    } else {
      showModalError(result.error || "Could not create project");
    }
  } catch (error) {
    showModalError(error.message);
  } finally {
    els.confirmCreate.disabled = false;
    els.confirmCreate.textContent = originalText;
  }
}

async function copyLoader() {
  try {
    await navigator.clipboard.writeText(els.loaderLine.textContent);
    els.copyLoader.textContent = "Copied";
    setTimeout(function () { els.copyLoader.textContent = "Copy"; }, 1200);
  } catch (error) {
    els.copyLoader.textContent = "Failed";
    setTimeout(function () { els.copyLoader.textContent = "Copy"; }, 1200);
  }
}

function openModal() {
  hideModalError();
  els.modal.classList.add("is-open");
  els.modal.setAttribute("aria-hidden", "false");
  els.nameInput.value = "";
  els.modeInput.value = "keyed";
  setTimeout(function () { els.nameInput.focus(); }, 50);
}

function closeModal() {
  els.modal.classList.remove("is-open");
  els.modal.setAttribute("aria-hidden", "true");
}

els.openCreate.addEventListener("click", openModal);
els.closeModal.addEventListener("click", closeModal);
els.cancelModal.addEventListener("click", closeModal);
els.confirmCreate.addEventListener("click", createProject);
els.saveProject.addEventListener("click", saveProject);
els.deleteProject.addEventListener("click", deleteProject);
els.copyLoader.addEventListener("click", copyLoader);

els.modal.addEventListener("click", function (event) {
  if (event.target.getAttribute("data-close") === "true") closeModal();
});

document.addEventListener("keydown", function (event) {
  if (event.key === "Escape") closeModal();
});

if (els.menuToggle && els.sidebar) {
  els.menuToggle.addEventListener("click", function () {
    els.sidebar.classList.toggle("is-open");
  });
}

if (els.themeToggle) {
  els.themeToggle.addEventListener("click", function () {
    document.body.classList.toggle("theme-light");
  });
}

loadProjects();
