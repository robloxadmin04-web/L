// owner.js
// Owner key admin. Talks to the backend using an owner token.
// The owner token is entered once and kept in sessionStorage for this tab.

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

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const d = new Date(value);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return year + "-" + month + "-" + day;
}

async function fetchKeys() {
  try {
    const result = await api("/api/keys", { method: "GET" });
    if (result.ok) {
      keys = result.keys || [];
      render();
    }
  } catch (error) {
    window.alert(error.message);
  }
}

function render() {
  const term = els.search.value.trim().toLowerCase();

  const filtered = keys.filter(function (item) {
    if (!term) {
      return true;
    }
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
  const revoked = keys.filter(function (k) {
    return k.revoked;
  }).length;
  els.statTotal.textContent = String(total);
  els.statActive.textContent = String(total - revoked);
  els.statRevoked.textContent = String(revoked);
}

async function copyKey(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(function () {
      button.textContent = original;
    }, 1200);
  } catch (error) {
    button.textContent = "Failed";
    setTimeout(function () {
      button.textContent = "Copy";
    }, 1200);
  }
}

async function updateKey(id, revoked) {
  try {
    const result = await api("/api/keys/" + id, {
      method: "PATCH",
      body: JSON.stringify({ revoked: revoked }),
    });
    if (result.ok) {
      fetchKeys();
    }
  } catch (error) {
    window.alert(error.message);
  }
}

async function deleteKey(id) {
  try {
    const result = await api("/api/keys/" + id, { method: "DELETE" });
    if (result.ok) {
      fetchKeys();
    }
  } catch (error) {
    window.alert(error.message);
  }
}

async function createKey() {
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
    }
  } catch (error) {
    window.alert(error.message);
  }
}

/* Modal */
function openModal() {
  els.modal.classList.add("is-open");
  els.modal.setAttribute("aria-hidden", "false");
  els.labelInput.value = "";
  els.prefixInput.value = "KF";
  setTimeout(function () {
    els.labelInput.focus();
  }, 50);
}

function closeModal() {
  els.modal.classList.remove("is-open");
  els.modal.setAttribute("aria-hidden", "true");
}

/* Events */
els.openGenerate.addEventListener("click", openModal);
els.closeModal.addEventListener("click", closeModal);
els.cancelModal.addEventListener("click", closeModal);
els.confirmGenerate.addEventListener("click", createKey);
els.search.addEventListener("input", render);

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

fetchKeys();
