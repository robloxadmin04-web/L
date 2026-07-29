/* Owner page key management. Demo storage only (localStorage). */
/* NOTE: keys stored client-side are visible in the browser. */
/* For real security, verify keys on a backend instead. */

const STORAGE_KEY = "kf_api_keys";

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

let keys = loadKeys();

/* Storage */
function loadKeys() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (error) {
    return [];
  }
}

function saveKeys() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
}

/* Key generation */
function randomBlock() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 4; i = i + 1) {
    out = out + chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

function makeKey(prefix) {
  const safePrefix =
    (prefix || "KF")
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "")
      .slice(0, 6) || "KF";
  return (
    safePrefix + "-" + randomBlock() + "-" + randomBlock() + "-" + randomBlock()
  );
}

function formatDate(timestamp) {
  const d = new Date(timestamp);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return year + "-" + month + "-" + day;
}

/* Rendering */
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
    dateTd.textContent = formatDate(item.created);

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
      item.revoked = !item.revoked;
      saveKeys();
      render();
    });

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "mini-btn is-danger";
    deleteBtn.type = "button";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", function () {
      keys = keys.filter(function (k) {
        return k.id !== item.id;
      });
      saveKeys();
      render();
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
  const active = total - revoked;

  els.statTotal.textContent = String(total);
  els.statActive.textContent = String(active);
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

function createKey() {
  const newKey = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    key: makeKey(els.prefixInput.value),
    label: els.labelInput.value.trim(),
    revoked: false,
    created: Date.now(),
  };

  keys.unshift(newKey);
  saveKeys();
  render();
  closeModal();
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

render();
