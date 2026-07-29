// server.js
// Backend for API key gating + projects + key-gated script delivery.
// Only this server talks to Supabase. The service_role key stays here.

const express = require("express");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const OWNER_TOKEN = process.env.OWNER_TOKEN;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !OWNER_TOKEN) {
  console.error("Missing SUPABASE_URL, SUPABASE_SERVICE_KEY, or OWNER_TOKEN");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false },
});

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// --- Helpers ---
function requireOwner(req, res, next) {
  const token = req.header("x-owner-token");
  if (!token || token !== OWNER_TOKEN) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

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

function makeSlug(name) {
  const base =
    String(name || "project")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40) || "project";
  return base + "-" + randomBlock().toLowerCase();
}

// ============================================================
// PUBLIC: verify a key (index.html login)
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
// PUBLIC: loader script delivery (called by loadstring in Roblox)
//   GET /v1/load/:slug?key=KF-XXXX
// Returns raw Lua text. Blocks if key is missing/invalid/revoked
// (unless the project is keyless).
// ============================================================
app.get("/v1/load/:slug", async (req, res) => {
  res.type("text/plain");

  const slug = req.params.slug;
  const key = (req.query.key ? String(req.query.key) : "").trim();

  const { data: project, error: projErr } = await supabase
    .from("projects")
    .select("id, script, key_mode")
    .eq("slug", slug)
    .maybeSingle();

  if (projErr || !project) {
    return res.status(404).send("-- project not found");
  }

  if (project.key_mode === "keyed") {
    if (!key) {
      return res.status(401).send("-- missing key");
    }
    const { data: keyRow } = await supabase
      .from("api_keys")
      .select("id, revoked")
      .eq("key", key)
      .maybeSingle();

    if (!keyRow || keyRow.revoked) {
      return res.status(403).send("-- invalid or revoked key");
    }

    await supabase
      .from("api_keys")
      .update({ last_used_at: new Date().toISOString() })
      .eq("id", keyRow.id);
    await supabase
      .from("access_log")
      .insert({ key_id: keyRow.id, event: "load", project_id: project.id });
  } else {
    await supabase
      .from("access_log")
      .insert({ event: "load", project_id: project.id });
  }

  return res.status(200).send(project.script || "-- empty script");
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
    const projectsRes = await supabase
      .from("projects")
      .select("id", { count: "exact", head: true });

    const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const loginsRes = await supabase
      .from("access_log")
      .select("id", { count: "exact", head: true })
      .eq("event", "login")
      .gte("created_at", dayAgo);
    const loadsRes = await supabase
      .from("access_log")
      .select("id", { count: "exact", head: true })
      .eq("event", "load")
      .gte("created_at", dayAgo);

    const total = totalRes.count || 0;
    const revoked = revokedRes.count || 0;

    return res.json({
      ok: true,
      stats: {
        total: total,
        active: total - revoked,
        revoked: revoked,
        logins24h: loginsRes.count || 0,
        loads24h: loadsRes.count || 0,
        projects: projectsRes.count || 0,
      },
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ============================================================
// OWNER: keys
// ============================================================
app.get("/api/keys", requireOwner, async (req, res) => {
  const { data, error } = await supabase
    .from("api_keys")
    .select("id, key, label, revoked, created_at, last_used_at, project_id")
    .order("created_at", { ascending: false });
  if (error) {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
  return res.json({ ok: true, keys: data });
});

app.post("/api/keys", requireOwner, async (req, res) => {
  const label = req.body && req.body.label ? String(req.body.label).trim() : "";
  const prefix = req.body && req.body.prefix ? String(req.body.prefix) : "KF";
  const projectId =
    req.body && req.body.project_id ? req.body.project_id : null;
  const key = makeKey(prefix);

  const { data, error } = await supabase
    .from("api_keys")
    .insert({ key: key, label: label, project_id: projectId })
    .select("id, key, label, revoked, created_at, last_used_at, project_id")
    .single();
  if (error) {
    return res.status(500).json({ ok: false, error: "Could not create key" });
  }
  return res.json({ ok: true, key: data });
});

app.patch("/api/keys/:id", requireOwner, async (req, res) => {
  const id = req.params.id;
  const revoked = !!(req.body && req.body.revoked);
  const { data, error } = await supabase
    .from("api_keys")
    .update({ revoked: revoked })
    .eq("id", id)
    .select("id, key, label, revoked, created_at, last_used_at, project_id")
    .single();
  if (error) {
    return res.status(500).json({ ok: false, error: "Could not update key" });
  }
  return res.json({ ok: true, key: data });
});

app.delete("/api/keys/:id", requireOwner, async (req, res) => {
  const { error } = await supabase
    .from("api_keys")
    .delete()
    .eq("id", req.params.id);
  if (error) {
    return res.status(500).json({ ok: false, error: "Could not delete key" });
  }
  return res.json({ ok: true });
});

// ============================================================
// OWNER: projects
// ============================================================
app.get("/api/projects", requireOwner, async (req, res) => {
  const { data, error } = await supabase
    .from("projects")
    .select("id, name, slug, key_mode, created_at")
    .order("created_at", { ascending: false });
  if (error) {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
  return res.json({ ok: true, projects: data });
});

app.get("/api/projects/:id", requireOwner, async (req, res) => {
  const { data, error } = await supabase
    .from("projects")
    .select("id, name, slug, script, key_mode, created_at")
    .eq("id", req.params.id)
    .single();
  if (error) {
    return res.status(500).json({ ok: false, error: "Not found" });
  }
  return res.json({ ok: true, project: data });
});

app.post("/api/projects", requireOwner, async (req, res) => {
  const name = req.body && req.body.name ? String(req.body.name).trim() : "";
  const script = req.body && req.body.script ? String(req.body.script) : "";
  const keyMode =
    req.body && req.body.key_mode === "keyless" ? "keyless" : "keyed";
  if (!name) {
    return res.status(400).json({ ok: false, error: "Missing project name" });
  }

  const { data, error } = await supabase
    .from("projects")
    .insert({
      name: name,
      slug: makeSlug(name),
      script: script,
      key_mode: keyMode,
    })
    .select("id, name, slug, key_mode, created_at")
    .single();
  if (error) {
    return res
      .status(500)
      .json({ ok: false, error: "Could not create project" });
  }
  return res.json({ ok: true, project: data });
});

app.patch("/api/projects/:id", requireOwner, async (req, res) => {
  const patch = {};
  if (req.body && typeof req.body.name === "string")
    patch.name = req.body.name.trim();
  if (req.body && typeof req.body.script === "string")
    patch.script = req.body.script;
  if (
    req.body &&
    (req.body.key_mode === "keyed" || req.body.key_mode === "keyless")
  )
    patch.key_mode = req.body.key_mode;

  const { data, error } = await supabase
    .from("projects")
    .update(patch)
    .eq("id", req.params.id)
    .select("id, name, slug, script, key_mode, created_at")
    .single();
  if (error) {
    return res
      .status(500)
      .json({ ok: false, error: "Could not update project" });
  }
  return res.json({ ok: true, project: data });
});

app.delete("/api/projects/:id", requireOwner, async (req, res) => {
  const { error } = await supabase
    .from("projects")
    .delete()
    .eq("id", req.params.id);
  if (error) {
    return res
      .status(500)
      .json({ ok: false, error: "Could not delete project" });
  }
  return res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
