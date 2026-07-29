// server.js
// Backend for API key gating. Only this server talks to Supabase.
// The service_role key stays here and is NEVER sent to the browser.

const express = require("express");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

// --- Environment variables (set these in Render) ---
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const OWNER_TOKEN = process.env.OWNER_TOKEN; // secret for owner admin actions

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !OWNER_TOKEN) {
  console.error("Missing SUPABASE_URL, SUPABASE_SERVICE_KEY, or OWNER_TOKEN");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false },
});

app.use(express.json());

// Serve the static site from /public
app.use(express.static(path.join(__dirname, "public")));

// --- Helper: require owner token on admin routes ---
function requireOwner(req, res, next) {
  const token = req.header("x-owner-token");
  if (!token || token !== OWNER_TOKEN) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// --- Helper: make a random key ---
function randomBlock() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 4; i = i + 1) {
    out = out + chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

function makeKey(prefix) {
  const safe =
    (prefix || "KF")
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "")
      .slice(0, 6) || "KF";
  return safe + "-" + randomBlock() + "-" + randomBlock() + "-" + randomBlock();
}

// ============================================================
// PUBLIC: verify a key (called by index.html login)
// ============================================================
app.post("/api/verify", async (req, res) => {
  const key = (req.body && req.body.key ? String(req.body.key) : "").trim();

  if (!key) {
    return res.status(400).json({ ok: false, error: "Missing key" });
  }

  const { data, error } = await supabase
    .from("api_keys")
    .select("id, revoked")
    .eq("key", key)
    .maybeSingle();

  if (error) {
    return res.status(500).json({ ok: false, error: "Server error" });
  }

  if (!data || data.revoked) {
    return res.status(200).json({ ok: false, error: "Invalid or revoked key" });
  }

  await supabase
    .from("api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", data.id);

  await supabase.from("access_log").insert({ key_id: data.id, event: "login" });

  return res.status(200).json({ ok: true });
});

// ============================================================
// OWNER: dashboard stats
// ============================================================
app.get("/api/stats", requireOwner, async (req, res) => {
  try {
    const totalRes = await supabase
      .from("api_keys")
      .select("id", { count: "exact", head: true });

    const revokedRes = await supabase
      .from("api_keys")
      .select("id", { count: "exact", head: true })
      .eq("revoked", true);

    const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const loginsRes = await supabase
      .from("access_log")
      .select("id", { count: "exact", head: true })
      .eq("event", "login")
      .gte("created_at", dayAgo);

    const total = totalRes.count || 0;
    const revoked = revokedRes.count || 0;
    const logins24h = loginsRes.count || 0;

    return res.json({
      ok: true,
      stats: {
        total: total,
        active: total - revoked,
        revoked: revoked,
        logins24h: logins24h,
      },
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ============================================================
// OWNER: list keys
// ============================================================
app.get("/api/keys", requireOwner, async (req, res) => {
  const { data, error } = await supabase
    .from("api_keys")
    .select("id, key, label, revoked, created_at, last_used_at")
    .order("created_at", { ascending: false });

  if (error) {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
  return res.json({ ok: true, keys: data });
});

// ============================================================
// OWNER: create key
// ============================================================
app.post("/api/keys", requireOwner, async (req, res) => {
  const label = req.body && req.body.label ? String(req.body.label).trim() : "";
  const prefix = req.body && req.body.prefix ? String(req.body.prefix) : "KF";
  const key = makeKey(prefix);

  const { data, error } = await supabase
    .from("api_keys")
    .insert({ key: key, label: label })
    .select("id, key, label, revoked, created_at, last_used_at")
    .single();

  if (error) {
    return res.status(500).json({ ok: false, error: "Could not create key" });
  }
  return res.json({ ok: true, key: data });
});

// ============================================================
// OWNER: revoke / restore key
// ============================================================
app.patch("/api/keys/:id", requireOwner, async (req, res) => {
  const id = req.params.id;
  const revoked = !!(req.body && req.body.revoked);

  const { data, error } = await supabase
    .from("api_keys")
    .update({ revoked: revoked })
    .eq("id", id)
    .select("id, key, label, revoked, created_at, last_used_at")
    .single();

  if (error) {
    return res.status(500).json({ ok: false, error: "Could not update key" });
  }
  return res.json({ ok: true, key: data });
});

// ============================================================
// OWNER: delete key
// ============================================================
app.delete("/api/keys/:id", requireOwner, async (req, res) => {
  const id = req.params.id;

  const { error } = await supabase.from("api_keys").delete().eq("id", id);

  if (error) {
    return res.status(500).json({ ok: false, error: "Could not delete key" });
  }
  return res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
