

(function () {
  const ACCOUNT_KEY = "sl_account";

  function getRole() {
    try {
      const raw = sessionStorage.getItem(ACCOUNT_KEY);
      if (!raw) return null;
      const account = JSON.parse(raw);
      return account && account.role ? String(account.role) : null;
    } catch (e) {
      return null;
    }
  }

  function hideOwnerNav() {
    const role = getRole();
    if (role === "owner") return;

    const groups = document.querySelectorAll(".nav-group");
    groups.forEach(function (g) {
      const title = g.querySelector(".nav-title");
      if (title && title.textContent.trim().toLowerCase() === "owner") {
        g.style.display = "none";
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", hideOwnerNav);
  } else {
    hideOwnerNav();
  }
})();
