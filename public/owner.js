// owner.js â€” Solaries Accounts admin (Phase 4b)
// Owner-only. Uses /api/accounts endpoints from server.js.

const el = {
  total: document.querySelector('[data-stat="total"]'),
  free: document.querySelector('[data-stat="free"]'),
  creator: document.querySelector('[data-stat="creator"]'),
  scale: document.querySelector('[data-stat="scale"]'),

  table: document.getElementById("acctTable"),
  body: document.getElementById("acctBody"),
  empty: document.getElementById("acctEmpty"),
  search: document.getElementById("searchInput"),
  tabs: document.querySelectorAll("#filterTabs .tab-btn"),
  notOwner: document.getElementById("notOwnerCard"),

  openCreate: document.getElementById("openCreate"),
  createModal: document.getElementById("createModal"),
  closeCreate: document.getElementById("closeCreate"),
  cancelCreate: document.getElementById("cancelCreate"),
  confirmCreate: document.getElementById("confirmCreate"),
  aName: document.getElementById("aName"),
  aPlan: document.getElementById("aPlan"),
  createErr: document.getElementById("createErr"),

  newKeyModal: document.getElementById("newKeyModal"),
  newKeyName: document.getElementById("newKeyName"),
  newKeyCode: document.getElementById("newKeyCode"),
  closeNewKey: document.getElementById("closeNewKey"),
  doneNewKey: document.getElementById("doneNewKey"),
  copyNewKey: document.getElementById("copyNewKey"),
};

let accounts = [];
let filter = "all";

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function formatDate(v) {
  if (!v) return "â€”";
  const d = new Date(v);
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
}

function timeAgo(v) {
  if (!v) return "Never";
  const then = new Date(v).getTime();
  const diff = Math.max(0, Date.now() - then);
  const sec = Math.round(diff / 1000);
  if (sec < 60) return sec + "s ago";
  const min = Math.round(sec / 60);
  if (min < 60) return min + "m ago";
  const hr = Math.round(min / 60);
  if (hr < 24) return hr + "h ago";
  const day = Math.round(hr / 24);
  return day + "d ago";
}

async function loadAccounts() {
  try {
    const r = await window.SL.api("/api/accounts");
    if (!r.ok) {
      if (r.error === "Owner only") {
        el.notOwner.style.display = "block";
        document.querySelector(".card").style.display = "none";
        document.querySelector(".stats-grid").style.display = "none";
        el.openCreate.style.display = "none";
      }
      throw new Error(r.error || "Could not load accounts");
    }
    accounts = r.accounts || [];
    render();
  } catch (e) {
    window.SL.toast(e.message, "error");
  }
}

function render() {
  const term = el.search.value.trim().toLowerCase();

  let list = accounts.slice();

  if (filter !== "all") list = list.filter(function (a) { return a.plan === filter; });

  if (term) {
    list = list.filter(function (a) {
      return (a.name || "").toLowerCase().includes(term) || a.api_key.toLowerCase().includes(term);
    });
  }

  // Stats
  el.total.textContent = accounts.length;
  el.free.textContent = accounts.filter(function (a) { return a.plan === "free"; }).length;
  el.creator.textContent = accounts.filter(function (a) { return a.plan === "creator"; }).length;
  el.scale.textContent = accounts.filter(function (a) { return a.plan === "scale"; }).length;

  // Tab counts
  document.querySelector('[data-count="all"]').textContent = accounts.length;
  document.querySelector('[data-count="free"]').textContent = accounts.filter(function (a) { return a.plan === "free"; }).length;
  document.querySelector('[data-count="creator"]').textContent = accounts.filter(function (a) { return a.plan === "creator"; }).length;
  document.querySelector('[data-count="scale"]').textContent = accounts.filter(function (a) { return a.plan === "scale"; }).length;

  el.body.innerHTML = "";
  if (list.length === 0) {
    el.table.style.display = "none";
    if (accounts.length === 0) {
      el.empty.style.display = "block";
    } else {
      el.empty.style.display = "none";
      const p = document.createElement("p");
      p.style.cssText = "text-align:center;color:var(--text-soft);padding:32px;";
      p.textContent = "No accounts match your filter.";
      el.body.parentNode.appendChild(p);
    }
    return;
  }
  el.table.style.display = "";
  el.empty.style.display = "none";

  list.forEach(function (a) {
    const tr = document.createElement("tr");
    const planClass = a.role === "owner" ? "is-owner" : ("is-" + a.plan);
    const planText = a.role === "owner" ? "OWNER" : a.plan.toUpperCase();
    const isSelf = window.SL.account && window.SL.account.account_id === a.id;

    tr.innerHTML =
      '<td><div class="cell-name">' + escapeHtml(a.name) + (isSelf ? ' <span style="color:var(--text-soft);font-weight:400;font-size:11px">(you)</span>' : '') + '</div></td>' +
      '<td><span class="api-code">' + escapeHtml(a.api_key) + '</span></td>' +
      '<td><span class="plan-pill ' + planClass + '">' + planText + '</span></td>' +
      '<td style="color:var(--text-soft)">' + timeAgo(a.last_login) + '</td>' +
      '<td style="color:var(--text-soft)">' + formatDate(a.created_at) + '</td>' +
      '<td>' +
        '<div class="row-actions">' +
          '<button class="mini-btn" data-copy>Copy</button>' +
          (a.role === "owner" || isSelf ? '' : '<button class="mini-btn is-danger" data-del>Delete</button>') +
        '</div>' +
      '</td>';

    tr.querySelector("[data-copy]").addEventListener("click", async function (e) {
      try {
        await navigator.clipboard.writeText(a.api_key);
        e.target.textContent = "Copied";
        setTimeout(function () { e.target.textContent = "Copy"; }, 1200);
      } catch (err) {
        window.SL.toast("Copy failed", "error");
      }
    });

    const delBtn = tr.querySelector("[data-del]");
    if (delBtn) {
      delBtn.addEventListener("click", async function () {
        if (!window.confirm("Delete account '" + a.name + "'? This removes all their projects, scripts, and keys.")) return;
        try {
          const r = await window.SL.api("/api/accounts/" + a.id, { method: "DELETE" });
          if (r.ok) { window.SL.toast("Account deleted", "ok"); loadAccounts(); }
          else window.SL.toast(r.error || "Could not delete", "error");
        } catch (e) { window.SL.toast(e.message, "error"); }
      });
    }

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

// Create modal
function openCreate() {
  el.aName.value = "";
  el.aPlan.value = "free";
  el.createErr.classList.remove("is-visible");
  el.createModal.classList.add("is-open");
  setTimeout(function () { el.aName.focus(); }, 50);
}
function closeCreate() { el.createModal.classList.remove("is-open"); }

el.openCreate.addEventListener("click", openCreate);
el.closeCreate.addEventListener("click", closeCreate);
el.cancelCreate.addEventListener("click", closeCreate);
el.createModal.addEventListener("click", function (e) {
  if (e.target.getAttribute("data-close") === "true") closeCreate();
});

el.confirmCreate.addEventListener("click", async function () {
  const name = el.aName.value.trim();
  if (!name) {
    el.createErr.textContent = "Name is required.";
    el.createErr.classList.add("is-visible");
    return;
  }
  el.confirmCreate.disabled = true;
  el.confirmCreate.textContent = "Issuing...";
  try {
    const r = await window.SL.api("/api/accounts", {
      method: "POST",
      body: JSON.stringify({ name: name, plan: el.aPlan.value }),
    });
    if (r.ok) {
      closeCreate();
      showNewKey(r.account.name, r.account.api_key);
      loadAccounts();
    } else {
      el.createErr.textContent = r.error || "Could not create account.";
      el.createErr.classList.add("is-visible");
    }
  } catch (e) {
    el.createErr.textContent = e.message;
    el.createErr.classList.add("is-visible");
  } finally {
    el.confirmCreate.disabled = false;
    el.confirmCreate.textContent = "Issue key";
  }
});

// New key modal
function showNewKey(name, key) {
  el.newKeyName.textContent = "For: " + name;
  el.newKeyCode.textContent = key;
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
  if (e.key === "Escape") { closeCreate(); closeNewKey(); }
});

loadAccounts();
