// bot.js - Solaries Discord page (v3)
// Cleaner script list, mobile-friendly, no "Primary" text
// Status badge now always shows "Solaries" (no Discord tag)

const INVITE_URL = "https://discord.com/oauth2/authorize?client_id=1532093570327121920&permissions=2416003136&integration_type=0&scope=bot+applications.commands";

const el = {
  chipBot: document.getElementById("chipBot"),
  chipBotText: document.getElementById("chipBotText"),
  chipScripts: document.getElementById("chipScripts"),
  chipScriptsText: document.getElementById("chipScriptsText"),
  chipLinked: document.getElementById("chipLinked"),
  chipLinkedText: document.getElementById("chipLinkedText"),

  btnInvite: document.getElementById("btnInvite"),

  scriptList: document.getElementById("scriptList"),
  emptyList: document.getElementById("emptyList"),

  toolsToggle: document.getElementById("toolsToggle"),
  tools: document.getElementById("tools"),
};

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

el.btnInvite.href = INVITE_URL;

el.toolsToggle.addEventListener("click", function () {
  el.tools.classList.toggle("is-open");
});

async function copyText(text, okMsg) {
  try {
    await navigator.clipboard.writeText(text);
    window.SL.toast(okMsg || "Copied", "ok");
  } catch (e) {
    window.SL.toast("Copy failed", "error");
  }
}

async function loadBotStatus() {
  try {
    const r = await window.SL.api("/api/discord/status");
    if (r.ok && r.status && r.status.online) {
      el.chipBot.classList.add("ok");
      el.chipBotText.textContent = "Bot online - Solaries";
    } else {
      el.chipBot.classList.add("warn");
      el.chipBotText.textContent = "Bot offline";
    }
  } catch (e) {
    el.chipBot.classList.add("warn");
    el.chipBotText.textContent = "Bot status unknown";
  }
}

async function loadLink() {
  try {
    const r = await window.SL.api("/api/discord/link");
    if (r.ok && r.linked) {
      el.chipLinked.classList.add("ok");
      el.chipLinkedText.textContent = "Linked as " + (r.linked.discord_username || "Discord user");
    } else {
      el.chipLinked.classList.add("warn");
      el.chipLinkedText.textContent = "Discord not linked";
    }
  } catch (e) {}
}

async function loadScripts() {
  try {
    const pr = await window.SL.api("/api/projects");
    if (!pr.ok) throw new Error(pr.error || "Could not load projects");
    const projects = pr.projects || [];

    if (projects.length === 0) {
      el.scriptList.innerHTML = "";
      el.emptyList.style.display = "block";
      el.chipScriptsText.textContent = "0 scripts";
      return;
    }

    const allScripts = [];
    await Promise.all(projects.map(async function (p) {
      try {
        const sr = await window.SL.api("/api/projects/" + p.id + "/scripts");
        if (sr.ok && sr.scripts) {
          sr.scripts.forEach(function (s) {
            allScripts.push({
              id: s.id, name: s.name, slug: s.slug,
              enabled: s.enabled, key_mode: s.key_mode,
              project_name: p.name,
            });
          });
        }
      } catch (e) {}
    }));

    el.chipScriptsText.textContent = allScripts.length + (allScripts.length === 1 ? " script" : " scripts");

    if (allScripts.length === 0) {
      el.scriptList.innerHTML = "";
      el.emptyList.style.display = "block";
      return;
    }

    el.emptyList.style.display = "none";
    el.scriptList.innerHTML = "";

    allScripts.forEach(function (s) {
      const cmd = "/panel script_id:" + s.slug;
      const row = document.createElement("div");
      row.className = "script-row";
      row.innerHTML =
        '<div class="script-icon">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h10l6 6v10a2 2 0 01-2 2H4a2 2 0 01-2-2V6a2 2 0 012-2z"/><path d="M14 4v6h6"/></svg>' +
        '</div>' +
        '<div class="script-info">' +
          '<p class="script-name">' + escapeHtml(s.name) + '</p>' +
          '<p class="script-meta">' +
            '<span>' + escapeHtml(s.project_name) + '</span>' +
            '<span class="tag ' + (s.enabled ? "on" : "off") + '">' + (s.enabled ? "On" : "Off") + '</span>' +
            '<span class="tag">' + (s.key_mode === "keyless" ? "Keyless" : "Keyed") + '</span>' +
          '</p>' +
        '</div>' +
        '<div class="script-action">' +
          '<button class="btn-mini is-accent" data-copy>Copy command</button>' +
        '</div>';

      row.querySelector("[data-copy]").addEventListener("click", function () {
        copyText(cmd, "Command copied");
      });

      el.scriptList.appendChild(row);
    });
  } catch (e) {
    window.SL.toast(e.message, "error");
    el.emptyList.style.display = "block";
  }
}

loadBotStatus();
loadLink();
loadScripts();
