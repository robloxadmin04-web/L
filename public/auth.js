// auth.js — Solaries session guard + fetch helper (Phase 1)
// Include this at the top of every authenticated page.
//
//   <script src="auth.js"></script>
//
// It does three things:
//   1. Redirects to index.html if there's no valid session token.
//   2. Exposes window.SL — { session, api(path, opts), signOut(), toast(msg, kind) }.
//   3. Wires common UI: sidebar menu toggle, theme toggle, sign-out link.

(function () {
  const TOKEN_KEY = "sl_session";
  const ACCOUNT_KEY = "sl_account";

  const token = sessionStorage.getItem(TOKEN_KEY);
  const accountRaw = sessionStorage.getItem(ACCOUNT_KEY);

  if (!token || !accountRaw) {
    window.location.replace("index.html");
    return;
  }

  let account;
  try {
    account = JSON.parse(accountRaw);
  } catch (e) {
    sessionStorage.clear();
    window.location.replace("index.html");
    return;
  }

  async function api(path, options) {
    const config = options || {};
    config.headers = Object.assign(
      { "Content-Type": "application/json", "x-session-token": token },
      config.headers || {}
    );

    let response;
    try {
      response = await fetch(path, config);
    } catch (e) {
      throw new Error("Cannot reach server. Check your connection.");
    }

    if (response.status === 401) {
      sessionStorage.clear();
      window.location.replace("index.html");
      throw new Error("Session expired.");
    }

    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch (e) {
      throw new Error("Server returned: " + text.slice(0, 120));
    }
  }

  async function signOut() {
    try { await api("/api/signout", { method: "POST" }); } catch (e) {}
    sessionStorage.clear();
    window.location.replace("index.html");
  }

  // Toast — bottom-right
  let toastEl;
  function toast(message, kind) {
    if (!toastEl) {
      toastEl = document.createElement("div");
      toastEl.className = "toast";
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = message;
    toastEl.className = "toast is-visible " + (kind === "error" ? "is-error" : "is-ok");
    setTimeout(function () { toastEl.className = "toast"; }, 2400);
  }

  // Wire up common UI once DOM is ready
  document.addEventListener("DOMContentLoaded", function () {
    // Fill user info if the elements exist
    const nameEl = document.querySelector("[data-user-name]");
    const planEl = document.querySelector("[data-user-plan]");
    const avatarEl = document.querySelector("[data-user-avatar]");
    if (nameEl) nameEl.textContent = account.name || "Account";
    if (planEl) planEl.textContent = account.role === "owner" ? "Owner" : (account.plan || "Free");
    if (avatarEl) {
      const initials = String(account.name || "??").split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase();
      avatarEl.textContent = initials || "?";
    }

    // Menu toggle
    const menuBtn = document.getElementById("menuToggle");
    const sidebar = document.getElementById("sidebar");
    if (menuBtn && sidebar) {
      menuBtn.addEventListener("click", function () {
        sidebar.classList.toggle("is-open");
      });
    }

    // Theme toggle placeholder — just toggles a class for future use
    const themeBtn = document.getElementById("themeToggle");
    if (themeBtn) {
      themeBtn.addEventListener("click", function () {
        document.body.classList.toggle("theme-light");
      });
    }

    // Sign out link
    document.querySelectorAll("[data-signout]").forEach(function (el) {
      el.addEventListener("click", function (e) {
        e.preventDefault();
        signOut();
      });
    });
  });

  window.SL = { account, api, signOut, toast };
})();
