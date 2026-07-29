// projects.js
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
    config.headers || {},
  );
  const response = await fetch(API_BASE + pathName, config);
  if (response.status === 401) {
    clearToken();
    throw new Error("Unauthorized. Wrong owner token.");
  }
  return response.json();
}

function loaderFor(project) {
  const base = window.location.origin;
  if (project.key_mode === "keyed") {
    return (
      'loadstring(game:HttpGet("' +
      base +
      "/v1/load/" +
      project.slug +
      '?key=YOUR_KEY", true))()'
    );
  }
  return (
    'loadstring(game:HttpGet("' +
    base +
    "/v1/load/" +
    project.slug +
    '", true))()'
  );
}

async function loadProjects() {
  try {
    const result = await api("/api/projects", { method: "GET" });
    if (result.ok) {
      projects = result.projects || [];
      renderList();
    }
  } catch (error) {
    window.alert(error.message);
  }
}

function renderList() {
  els.list.innerHTML = "";

  projects.forEach(function (p) {
    const item = document.createElement("div");
    item.className =
      "project-item" + (current && current.id === p.id ? " is-active" : "");

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
    item.addEventListener("click", function () {
      openProject(p.id);
    });

    els.list.appendChild(item);
  });

  const hasRows = projects.length > 0;
  els.empty.style.display = hasRows ? "none" : "block";
}

async function openProject(id) {
  try {
    const result = await api("/api/projects/" + id, { method: "GET" });
    if (!result.ok) {
      return;
    }
    current = result.project;
    els.detail.style.display = "block";
    els.detailName.textContent = current.name;
    els.loaderLine.textContent = loaderFor(current);
    els.loaderHint.textContent =
      current.key_mode === "keyed"
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
  if (!current) {
    return;
  }
  try {
    const result = await api("/api/projects/" + current.id, {
      method: "PATCH",
      body: JSON.stringify({
        script: els.scriptInput.value,
        key_mode: els.keyModeSelect.value,
      }),
    });
    if (result.ok) {
      current = result.project;
      els.loaderLine.textContent = loaderFor(current);
      els.loaderHint.textContent =
        current.key_mode === "keyed"
          ? "Replace YOUR_KEY with an active API key before sharing."
          : "Keyless project. Anyone with this line can load it.";
      els.saveStatus.textContent = "Saved";
      els.saveStatus.className = "save-status is-ok";
      setTimeout(function () {
        els.saveStatus.textContent = "";
        els.saveStatus.className = "save-status";
      }, 1600);
      loadProjects();
    }
  } catch (error) {
    window.alert(error.message);
  }
}

async function deleteProject() {
  if (!current) {
    return;
  }
  if (!window.confirm("Delete this project permanently?")) {
    return;
  }
  try {
    const result = await api("/api/projects/" + current.id, {
      method: "DELETE",
    });
    if (result.ok) {
      current = null;
      els.detail.style.display = "none";
      loadProjects();
    }
  } catch (error) {
    window.alert(error.message);
  }
}

async function createProject() {
  const name = els.nameInput.value.trim();
  if (!name) {
    window.alert("Enter a project name.");
    return;
  }
  try {
    const result = await api("/api/projects", {
      method: "POST",
      body: JSON.stringify({ name: name, key_mode: els.modeInput.value }),
    });
    if (result.ok) {
      closeModal();
      await loadProjects();
      openProject(result.project.id);
    }
  } catch (error) {
    window.alert(error.message);
  }
}

async function copyLoader() {
  try {
    await navigator.clipboard.writeText(els.loaderLine.textContent);
    els.copyLoader.textContent = "Copied";
    setTimeout(function () {
      els.copyLoader.textContent = "Copy";
    }, 1200);
  } catch (error) {
    els.copyLoader.textContent = "Failed";
    setTimeout(function () {
      els.copyLoader.textContent = "Copy";
    }, 1200);
  }
}

function openModal() {
  els.modal.classList.add("is-open");
  els.modal.setAttribute("aria-hidden", "false");
  els.nameInput.value = "";
  els.modeInput.value = "keyed";
  setTimeout(function () {
    els.nameInput.focus();
  }, 50);
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
  if (event.target.getAttribute("data-close") === "true") {
    closeModal();
  }
});

document.addEventListener("keydown", function (event) {
  if (event.key === "Escape") {
    closeModal();
  }
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
