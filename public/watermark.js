// watermark.js - Solaries Watermark Trace page
// Paste a leaked/dumped copy of a delivered script; decodes the hidden
// "--[[wm:...]]" marker via POST /api/watermark/decode to find which
// key/device/time it was served to, with a one-click revoke.

const el = {
  input: document.getElementById("wmInput"),
  decodeBtn: document.getElementById("wmDecodeBtn"),
  revokeBtn: document.getElementById("wmRevokeBtn"),
  result: document.getElementById("wmResult"),
  grid: document.getElementById("wmGrid"),
  empty: document.getElementById("wmEmpty"),
};

let lastMatchedKeyId = null;

function fmtDate(v) {
  if (!v) return "Unknown";
  const d = new Date(v);
  if (isNaN(d.getTime())) return "Unknown";
  return d.toLocaleString();
}

function field(label, value) {
  const wrap = document.createElement("div");
  wrap.className = "wm-field";
  const l = document.createElement("div");
  l.className = "wm-field-label";
  l.textContent = label;
  const v = document.createElement("div");
  v.className = "wm-field-value";
  v.textContent = value == null || value === "" ? "—" : String(value);
  wrap.appendChild(l);
  wrap.appendChild(v);
  return wrap;
}

function showEmpty(message) {
  el.result.style.display = "none";
  el.revokeBtn.style.display = "none";
  el.empty.style.display = "block";
  el.empty.textContent = message;
}

function showResult(data) {
  el.empty.style.display = "none";
  el.grid.innerHTML = "";
  const wm = data.watermark || {};
  const key = data.key || null;

  el.grid.appendChild(field("Served at", fmtDate(wm.served_at)));
  el.grid.appendChild(field("HWID (prefix)", wm.hwid_prefix));
  el.grid.appendChild(field("IP at time of load", wm.ip));

  if (key) {
    el.grid.appendChild(field("Key", key.key));
    el.grid.appendChild(field("Label", key.label));
    el.grid.appendChild(field("Status", key.revoked ? "Revoked" : "Active"));
    el.grid.appendChild(field("HWID locked to", key.hwid));
    el.grid.appendChild(field("Expires", key.expires_at ? fmtDate(key.expires_at) : "Never"));
    lastMatchedKeyId = key.id;
    el.revokeBtn.style.display = key.revoked ? "none" : "inline-flex";
    el.revokeBtn.textContent = data.revoked ? "Revoked" : "Revoke this key now";
  } else {
    el.grid.appendChild(field("Key", "Not found in your account (deleted, keyless delivery, or belongs to a different account)"));
    lastMatchedKeyId = null;
    el.revokeBtn.style.display = "none";
  }

  el.result.style.display = "block";
}

async function decode(withRevoke) {
  const text = (el.input.value || "").trim();
  if (!text) {
    window.SL.toast("Paste the leaked script text first.", "error");
    return;
  }

  el.decodeBtn.disabled = true;
  try {
    const path = "/api/watermark/decode" + (withRevoke ? "?revoke=1" : "");
    const data = await window.SL.api(path, {
      method: "POST",
      body: JSON.stringify({ text }),
    });

    if (!data || data.ok === false) {
      showEmpty((data && data.error) || "No watermark found in the pasted text.");
      return;
    }

    showResult(data);
    if (withRevoke && data.revoked) {
      window.SL.toast("Key revoked.", "ok");
    } else if (withRevoke && !data.revoked) {
      window.SL.toast("Watermark decoded, but the key could not be revoked (already revoked or not found).", "error");
    } else {
      window.SL.toast("Watermark decoded.", "ok");
    }
  } catch (e) {
    showEmpty(e && e.message ? e.message : "Something went wrong decoding that text.");
  } finally {
    el.decodeBtn.disabled = false;
  }
}

el.decodeBtn.addEventListener("click", function () {
  decode(false);
});

el.revokeBtn.addEventListener("click", function () {
  if (!lastMatchedKeyId) return;
  if (!window.confirm("Revoke this key now? This immediately blocks it from loading any script.")) return;
  decode(true);
});
