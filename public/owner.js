// owner.js â€” with visible error messages inside the modal
// Owner key admin. Talks to the backend using an owner token.

const API_BASE = "";
const TOKEN_KEY = "kf_owner_token";

const els = {
  statTotal: document.getElementById("statTotal"),
  statActive: document.getElementById("statActive"),
  statRevoked: document.getElementById("statRevoked"),
  body: document.getElementById("keysBody"),
  emptyState: document.getElementById("emptyState"),
  table: document.getElementById("keysTable"),
  search: document.getElementById("searchInput"),
  openGenerate: document.getElementById("openGenerate"),
  modal: document.getElementById("generateModal"),
  closeModal: document.getElementById("closeModal"),
  cancelModal: document.getElementById("cancelModal"),
  confirmGenerate: document.getElementById("confirmGenerate"),
  labelInput: document.getElementById("labelInput"),
  prefixInput: document.getElementById("prefixInput"),
  menuToggle: document.getElementById("menuToggle"),
  sidebar: document.getElementById("sidebar"),
  themeToggle: document.getElementById("themeToggle"),
};

let keys = [];
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

function formatDate(value) {
  if (!value) return "-";
  const d = new Date(value);
  return d.getFullYear() + "-" +
    String(d.getMonth() + 1).padStart(2, "0") + "-" +
    String(d.getDate()).padStart(2, "0");
}

async function fetchKeys() {
  try {
    const result = await api("/api/keys", { method: "GET" });
    if (result.ok) {
      keys = result.keys || [];
      render();
    } else {
      window.alert(result.error || "Could not load keys");
    }
  } catch (error) {
    window.alert(error.message);
  }
}

function render() {
  const term = els.search.value.trim().toLowerCase();
  const filtered = keys.filter(function (item) {
    if (!term) return true;
    const label = (item.label || "").toLowerCase();
    return item.key.toLowerCase().includes(term) || label.includes(term);
  });

  els.body.innerHTML = "";
  filtered.forEach(function (item) {
    const tr = document.createElement("tr");

    const keyTd = document.createElement("td");
    const keySpan = document.createElement("span");
    keySpan.className = "key-code";
    keySpan.textContent = item.key;
    keyTd.appendChild(keySpan);

    const labelTd = document.createElement("td");
    labelTd.textContent = item.label || "No label";

    const statusTd = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "status-pill " + (item.revoked ? "is-revoked" : "is-live");
    pill.textContent = item.revoked ? "Revoked" : "Active";
    statusTd.appendChild(pill);

    const dateTd = document.createElement("td");
    dateTd.textContent = formatDate(item.created_at);

    const actionTd = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";

    const copyBtn = document.createElement("button");
    copyBtn.className = "mini-btn";
    copyBtn.type = "button";
    copyBtn.textContent = "Copy";
    copyBtn.addEventListener("click", function () {
      copyKey(item.key, copyBtn);
    });

    const toggleBtn = document.createElement("button");
    toggleBtn.className = "mini-btn is-danger";
    toggleBtn.type = "button";
    toggleBtn.textContent = item.revoked ? "Restore" : "Revoke";
    toggleBtn.addEventListener("click", function () {
      updateKey(item.id, !item.revoked);
    });

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "mini-btn is-danger";
    deleteBtn.type = "button";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", function () {
      if (window.confirm("Delete this key permanently?")) {
        deleteKey(item.id);
      }
    });

    actions.appendChild(copyBtn);
    actions.appendChild(toggleBtn);
    actions.appendChild(deleteBtn);
    actionTd.appendChild(actions);

    tr.appendChild(keyTd);
    tr.appendChild(labelTd);
    tr.appendChild(statusTd);
    tr.appendChild(dateTd);
    tr.appendChild(actionTd);

    els.body.appendChild(tr);
  });

  const hasRows = filtered.length > 0;
  els.table.style.display = hasRows ? "table" : "none";
  els.emptyState.style.display = hasRows ? "none" : "block";
  updateStats();
}

function updateStats() {
  const total = keys.length;
  const revoked = keys.filter(function (k) { return k.revoked; }).length;
  els.statTotal.textContent = String(total);
  els.statActive.textContent = String(total - revoked);
  els.statRevoked.textContent = String(revoked);
}

async function copyKey(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(function () { button.textContent = original; }, 1200);
  } catch (error) {
    button.textContent = "Failed";
    setTimeout(function () { button.textContent = "Copy"; }, 1200);
  }
}

async function updateKey(id, revoked) {
  try {
    const result = await api("/api/keys/" + id, {
      method: "PATCH",
      body: JSON.stringify({ revoked: revoked }),
    });
    if (result.ok) fetchKeys();
    else window.alert(result.error || "Could not update key");
  } catch (error) {
    window.alert(error.message);
  }
}

async function deleteKey(id) {
  try {
    const result = await api("/api/keys/" + id, { method: "DELETE" });
    if (result.ok) fetchKeys();
    else window.alert(result.error || "Could not delete key");
  } catch (error) {
    window.alert(error.message);
  }
}

async function createKey() {
  hideModalError();
  els.confirmGenerate.disabled = true;
  const originalText = els.confirmGenerate.textContent;
  els.confirmGenerate.textContent = "Creating...";

  try {
    const result = await api("/api/keys", {
      method: "POST",
      body: JSON.stringify({
        label: els.labelInput.value.trim(),
        prefix: els.prefixInput.value.trim(),
      }),
    });

    if (result.ok) {
      closeModal();
      fetchKeys();
    } else {
      showModalError(result.error || "Could not create key");
    }
  } catch (error) {
    showModalError(error.message);
  } finally {
    els.confirmGenerate.disabled = false;
    els.confirmGenerate.textContent = originalText;
  }
}

function openModal() {
  hideModalError();
  els.modal.classList.add("is-open");
  els.modal.setAttribute("aria-hidden", "false");
  els.labelInput.value = "";
  els.prefixInput.value = "KF";
  setTimeout(function () { els.labelInput.focus(); }, 50);
}

function closeModal() {
  els.modal.classList.remove("is-open");
  els.modal.setAttribute("aria-hidden", "true");
}

els.openGenerate.addEventListener("click", openModal);
els.closeModal.addEventListener("click", closeModal);
els.cancelModal.addEventListener("click", closeModal);
els.confirmGenerate.addEventListener("click", createKey);
els.search.addEventListener("input", render);

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

fetchKeys();
