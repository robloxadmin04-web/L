// dashboard.js â€” Solaries dashboard (Phase 1)
// Loads live stats for the signed-in account.

(async function () {
  try {
    const result = await window.SL.api("/api/stats");
    if (!result.ok) {
      window.SL.toast(result.error || "Could not load stats", "error");
      return;
    }
    const s = result.stats;
    const limits = result.limits;

    document.querySelector('[data-stat="projects"]').textContent =
      s.projects + " / " + limits.max_projects;
    document.querySelector('[data-stat="scripts"]').textContent = s.scripts;
    document.querySelector('[data-stat="keys"]').textContent =
      s.keys + " / " + limits.max_keys;
    document.querySelector('[data-stat="loads"]').textContent = s.loads_24h;

    const metaProjects = document.querySelector('[data-stat-meta="projects"]');
    if (metaProjects) metaProjects.textContent = limits.max_projects - s.projects + " remaining";

    const metaKeys = document.querySelector('[data-stat-meta="keys"]');
    if (metaKeys) metaKeys.textContent = s.active_keys + " active / " + s.revoked_keys + " revoked";

    const metaScripts = document.querySelector('[data-stat-meta="scripts"]');
    if (metaScripts) metaScripts.textContent = "Up to " + limits.max_scripts_per_project + " per project";
  } catch (error) {
    window.SL.toast(error.message, "error");
  }
})();
