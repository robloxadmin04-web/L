// auth.js — Solaries session guard + fetch helper (Phase 6 - theme toggle)
// Include this at the top of every authenticated page.
//
//   <script src="auth.js"></script>
//
// It does three things:
//   1. Redirects to index.html if there's no valid session token.
//   2. Exposes window.SL — { session, api(path, opts), signOut(), toast(msg, kind) }.
//   3. Wires common UI: sidebar menu toggle, theme toggle (light/dark), sign-out link.

(function () {
  const TOKEN_KEY = "sl_session";
  const ACCOUNT_KEY = "sl_account";
  const THEME_KEY = "sl_theme";

  // ----------------------------------------------------------
  // Theme: apply saved choice as early as possible (no flash).
  // Runs immediately, before DOMContentLoaded, so the correct
  // theme is set the moment the page starts rendering.
  // ----------------------------------------------------------
  function applyTheme(theme) {
    if (theme === "light") {
      document.documentElement.setAttribute("data-theme", "light");
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  }
  const savedTheme = localStorage.getItem(THEME_KEY) || "dark";
  applyTheme(savedTheme);

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

  // Update the theme button icon to match the current theme.
  // Shows a moon when in light mode (tap to go dark),
  // shows a sun when in dark mode (tap to go light).
  function updateThemeIcon(btn, theme) {
    if (!btn) return;
    const sun =
      '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/>' +
      '<path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
    const moon =
      '<svg viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/></svg>';
    btn.innerHTML = theme === "light" ? moon : sun;
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

    // Theme toggle — light / dark, saved in localStorage.
    const themeBtn = document.getElementById("themeToggle");
    if (themeBtn) {
      let current = localStorage.getItem(THEME_KEY) || "dark";
      updateThemeIcon(themeBtn, current);
      themeBtn.addEventListener("click", function () {
        current = current === "light" ? "dark" : "light";
        localStorage.setItem(THEME_KEY, current);
        applyTheme(current);
        updateThemeIcon(themeBtn, current);
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
