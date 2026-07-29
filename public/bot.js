// bot.js - Solaries Discord/Bot page
// Shows bot status, per-script panel commands, and the invite link.

const INVITE_URL = "https://discord.com/oauth2/authorize?client_id=1532093570327121920&permissions=2416003136&integration_type=0&scope=bot+applications.commands";
const SUPPORT_URL = "https://discord.com/oauth2/authorize?client_id=1532093570327121920&permissions=2416003136&integration_type=0&scope=bot+applications.commands";

const el = {
  chipBot: document.getElementById("chipBot"),
  chipBotText: document.getElementById("chipBotText"),
  chipScripts: document.getElementById("chipScripts"),
  chipScriptsText: document.getElementById("chipScriptsText"),
  chipLinked: document.getElementById("chipLinked"),
  chipLinkedText: document.getElementById("chipLinkedText"),

  btnInvite: document.getElementById("btnInvite"),
  btnSupport: document.getElementById("btnSupport"),
  apiKeyBox: document.getElementById("apiKeyBox"),
  btnCopyKey: document.getElementById("btnCopyKey"),

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

// Set invite URLs
el.btnInvite.href = INVITE_URL;
el.btnSupport.href = SUPPORT_URL;

// Expander toggle
el.toolsToggle.addEventListener("click", function () {
  el.tools.classList.toggle("is-open");
});

// Copy helper
async function copyText(text, okMsg) {
  try {
    await navigator.clipboard.writeText(text);
    window.SL.toast(okMsg || "Copied", "ok");
  } catch (e) {
    window.SL.toast("Copy failed", "error");
  }
}

// Load bot status
async function loadBotStatus() {
  try {
    const r = await window.SL.api("/api/discord/status");
    if (r.ok && r.status && r.status.online) {
      el.chipBot.classList.add("is-ok");
      el.chipBotText.textContent = "Bot online" + (r.status.username ? " - " + r.status.username : "");
    } else {
      el.chipBot.classList.add("is-warn");
      el.chipBotText.textContent = "Bot offline";
    }
  } catch (e) {
    el.chipBot.classList.add("is-warn");
    el.chipBotText.textContent = "Bot status unknown";
  }
}

// Load Discord link
async function loadLink() {
  try {
    const r = await window.SL.api("/api/discord/link");
    if (r.ok && r.linked) {
      el.chipLinked.classList.add("is-ok");
      el.chipLinkedText.textContent = "Linked as " + (r.linked.discord_username || "Discord user");
    } else {
      el.chipLinked.classList.add("is-warn");
      el.chipLinkedText.textContent = "Discord not linked - run /login";
    }
  } catch (e) {}
}

// Load API key (from /api/me - session carries the api_key? No, need accounts fetch)
async function loadApiKey() {
  try {
    // Fetch full account info - owner uses /api/accounts, users need another endpoint
    // For simplicity, show hint if session's own key is not exposed
    const r = await window.SL.api("/api/me");
    if (r.ok && r.account) {
      // Session doesn't expose api_key for security. Show placeholder with instructions.
      el.apiKeyBox.textContent = "Get your key from the sign-in page or from Accounts (owner)";
      el.apiKeyBox.style.fontSize = "12px";
      el.apiKeyBox.style.color = "var(--text-muted)";
      el.btnCopyKey.textContent = "Sign-in";
      el.btnCopyKey.addEventListener("click", function () {
        window.location.href = "index.html";
      });
    }
  } catch (e) {
    el.apiKeyBox.textContent = "Could not load key info";
  }
}

// Load all scripts across all projects and render per-script panel commands
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

    // Fetch scripts for each project in parallel
    const allScripts = [];
    await Promise.all(projects.map(async function (p) {
      try {
        const sr = await window.SL.api("/api/projects/" + p.id + "/scripts");
        if (sr.ok && sr.scripts) {
          sr.scripts.forEach(function (s) {
            allScripts.push({
              id: s.id,
              name: s.name,
              slug: s.slug,
              enabled: s.enabled,
              key_mode: s.key_mode,
              project_name: p.name,
              project_id: p.id,
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
      const item = document.createElement("div");
      item.className = "script-panel-item";
      item.innerHTML =
        '<div class="script-panel-meta">' +
          '<p class="script-panel-name">' + escapeHtml(s.name) + '</p>' +
          '<p class="script-panel-sub">' +
            '<span>' + escapeHtml(s.project_name) + '</span>' +
            '<span class="dot"></span>' +
            '<span>' + (s.enabled ? "On" : "Off") + '</span>' +
            '<span class="dot"></span>' +
            '<span>' + (s.key_mode === "keyless" ? "Keyless" : "Keyed") + '</span>' +
          '</p>' +
        '</div>' +
        '<div class="script-panel-actions">' +
          '<span class="script-cmd">' + escapeHtml(cmd) + '</span>' +
          '<button class="btn is-primary" data-copy>Copy ID</button>' +
        '</div>';

      item.querySelector("[data-copy]").addEventListener("click", function () {
        copyText(cmd, "Command copied");
      });

      el.scriptList.appendChild(item);
    });
  } catch (e) {
    window.SL.toast(e.message, "error");
    el.emptyList.style.display = "block";
  }
}

// Init
loadBotStatus();
loadLink();
loadApiKey();
loadScripts();
