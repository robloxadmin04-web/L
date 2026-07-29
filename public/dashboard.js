// dashboard.js
// Owner-facing dashboard. Pulls live stats from the backend.
// Requires the owner token (same one used on owner.html).

const API_BASE = "";
const TOKEN_KEY = "kf_owner_token";

const sidebar = document.getElementById("sidebar");
const menuToggle = document.getElementById("menuToggle");
const themeToggle = document.getElementById("themeToggle");
const navLinks = document.querySelectorAll(".nav-link");
const pageTitle = document.querySelector(".page-title");
const tabs = document.querySelectorAll(".tab");
const tabPanels = document.querySelectorAll(".tab-panel");

/* Stat value elements (matched by data-stat attribute in the HTML) */
const statEls = {
  total: document.querySelector('[data-stat="total"]'),
  active: document.querySelector('[data-stat="active"]'),
  revoked: document.querySelector('[data-stat="revoked"]'),
  logins24h: document.querySelector('[data-stat="logins24h"]'),
};

const keysBody = document.getElementById("keysBody");
const keysTable = document.getElementById("keysTable");
const keysEmpty = document.getElementById("keysEmpty");

/* Owner token */
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

async function api(pathName) {
  const token = getToken();
  const response = await fetch(API_BASE + pathName, {
    headers: { "x-owner-token": token || "" },
  });

  if (response.status === 401) {
    clearToken();
    throw new Error("Unauthorized. Wrong owner token.");
  }
  return response.json();
}

function setText(el, value) {
  if (el) {
    el.textContent = String(value);
  }
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

/* Load stats */
async function loadStats() {
  try {
    const result = await api("/api/stats");
    if (result.ok) {
      setText(statEls.total, result.stats.total);
      setText(statEls.active, result.stats.active);
      setText(statEls.revoked, result.stats.revoked);
      setText(statEls.logins24h, result.stats.logins24h);
    }
  } catch (error) {
    window.alert(error.message);
  }
}

/* Load keys into the Keys tab */
async function loadKeys() {
  if (!keysBody) {
    return;
  }
  try {
    const result = await api("/api/keys");
    if (!result.ok) {
      return;
    }

    const keys = result.keys || [];
    keysBody.innerHTML = "";

    keys.forEach(function (item) {
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
      pill.className =
        "status-pill " + (item.revoked ? "is-revoked" : "is-live");
      pill.textContent = item.revoked ? "Revoked" : "Active";
      statusTd.appendChild(pill);

      const dateTd = document.createElement("td");
      dateTd.textContent = formatDate(item.created_at);

      tr.appendChild(keyTd);
      tr.appendChild(labelTd);
      tr.appendChild(statusTd);
      tr.appendChild(dateTd);

      keysBody.appendChild(tr);
    });

    const hasRows = keys.length > 0;
    if (keysTable) {
      keysTable.style.display = hasRows ? "table" : "none";
    }
    if (keysEmpty) {
      keysEmpty.style.display = hasRows ? "none" : "block";
    }
  } catch (error) {
    window.alert(error.message);
  }
}

/* Mobile sidebar */
if (menuToggle && sidebar) {
  menuToggle.addEventListener("click", function () {
    sidebar.classList.toggle("is-open");
  });
}

window.addEventListener("resize", function () {
  if (window.innerWidth > 980 && sidebar) {
    sidebar.classList.remove("is-open");
  }
});

/* Sidebar navigation active state */
navLinks.forEach(function (link) {
  link.addEventListener("click", function (event) {
    const href = link.getAttribute("href");
    if (href && href.indexOf("#") !== 0) {
      return; // real page link, let it navigate
    }
    event.preventDefault();

    navLinks.forEach(function (item) {
      item.classList.remove("is-active");
    });
    link.classList.add("is-active");

    const label = link.querySelector("span:last-child");
    if (label && pageTitle) {
      pageTitle.textContent = label.textContent;
    }

    if (window.innerWidth <= 980 && sidebar) {
      sidebar.classList.remove("is-open");
    }
  });
});

/* Tabs */
tabs.forEach(function (tab) {
  tab.addEventListener("click", function () {
    const target = tab.getAttribute("data-tab");

    tabs.forEach(function (item) {
      item.classList.remove("is-active");
    });
    tab.classList.add("is-active");

    tabPanels.forEach(function (panel) {
      const isMatch = panel.getAttribute("data-panel") === target;
      panel.classList.toggle("is-active", isMatch);
    });

    if (target === "keys") {
      loadKeys();
    }
  });
});

/* Theme toggle */
if (themeToggle) {
  themeToggle.addEventListener("click", function () {
    document.body.classList.toggle("theme-light");
  });
}

/* Init */
loadStats();
loadKeys();
