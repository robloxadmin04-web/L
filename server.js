// server.js â€” Solaries multi-tenant backend (Phase 0)
// Every request is scoped to the authenticated account.

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false },
});

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// Session store â€” maps session_token -> account
// In-memory for now; sessions reset on redeploy.
// ============================================================
const sessions = new Map();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function createSession(account) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    account_id: account.id,
    role: account.role,
    plan: account.plan,
    name: account.name,
    expires_at: Date.now() + SESSION_TTL_MS,
  });
  return token;
}

function getSession(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires_at) {
    sessions.delete(token);
    return null;
  }
  return s;
}

// ============================================================
// Middleware: require a valid session (any account)
// ============================================================
async function requireAuth(req, res, next) {
  const token = req.header("x-session-token");
  const session = token ? getSession(token) : null;
  if (!session) {
    return res.status(401).json({ ok: false, error: "Not signed in" });
  }
  req.session = session;
  next();
}

// Middleware: require owner role
function requireOwner(req, res, next) {
  if (!req.session || req.session.role !== "owner") {
    return res.status(403).json({ ok: false, error: "Owner only" });
  }
  next();
}

// ============================================================
// Helpers
// ============================================================
function randomBlock() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 4; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

function makeKey(prefix) {
  const safe = (prefix || "KF").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 6) || "KF";
  return `${safe}-${randomBlock()}-${randomBlock()}-${randomBlock()}`;
}

function makeSlug(name) {
  const base = String(name || "item")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "item";
  return base + "-" + randomBlock().toLowerCase();
}

async function getPlanLimits(plan) {
  const { data } = await supabase.from("plan_limits").select("*").eq("plan", plan).maybeSingle();
  return data || { max_projects: 1, max_scripts_per_project: 3, max_keys: 50, max_obfuscations_per_month: 20 };
}

// ============================================================
// PUBLIC: sign in with API key (index.html)
// ============================================================
app.post("/api/signin", async (req, res) => {
  const apiKey = (req.body?.key || "").trim();
  if (!apiKey) return res.status(400).json({ ok: false, error: "Missing key" });

  const { data: account, error } = await supabase
    .from("accounts")
    .select("id, name, api_key, plan, role")
    .eq("api_key", apiKey)
    .maybeSingle();

  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  if (!account) return res.json({ ok: false, error: "Invalid API key" });

  await supabase.from("accounts").update({ last_login: new Date().toISOString() }).eq("id", account.id);
  await supabase.from("access_log").insert({ owner_account_id: account.id, event: "login" });

  const token = createSession(account);
  return res.json({
    ok: true,
    token,
    account: { id: account.id, name: account.name, plan: account.plan, role: account.role },
  });
});

app.post("/api/signout", requireAuth, (req, res) => {
  const token = req.header("x-session-token");
  sessions.delete(token);
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, async (req, res) => {
  const limits = await getPlanLimits(req.session.plan);
  res.json({ ok: true, account: req.session, limits });
});

// ============================================================
// PUBLIC: loader delivery (called by loadstring in Roblox)
//   GET /v1/load/:script_slug?key=KF-XXXX
// ============================================================
app.get("/v1/load/:script_slug", async (req, res) => {
  res.type("text/plain");
  const scriptSlug = req.params.script_slug;
  const key = (req.query.key || "").trim();

  const { data: script } = await supabase
    .from("scripts")
    .select("id, project_id, source, key_mode, enabled")
    .eq("slug", scriptSlug)
    .maybeSingle();

  if (!script) return res.status(404).send("-- script not found");
  if (!script.enabled) return res.status(403).send("-- script disabled");

  if (script.key_mode === "keyed") {
    if (!key) return res.status(401).send("-- missing key");

    const { data: keyRow } = await supabase
      .from("keys")
      .select("id, revoked, project_id, owner_account_id")
      .eq("key", key)
      .maybeSingle();

    if (!keyRow || keyRow.revoked) {
      return res.status(403).send("-- invalid or revoked key");
    }
    // If the key is tied to a project, it must match this script's project
    if (keyRow.project_id && keyRow.project_id !== script.project_id) {
      return res.status(403).send("-- key not valid for this script");
    }

    await supabase.from("keys").update({ last_used_at: new Date().toISOString() }).eq("id", keyRow.id);
    await supabase.from("access_log").insert({
      owner_account_id: keyRow.owner_account_id,
      key_id: keyRow.id,
      project_id: script.project_id,
      script_id: script.id,
      event: "load",
    });
  } else {
    await supabase.from("access_log").insert({
      project_id: script.project_id,
      script_id: script.id,
      event: "load",
    });
  }

  return res.status(200).send(script.source || "-- empty script");
});

// ============================================================
// STATS for signed-in account
// ============================================================
app.get("/api/stats", requireAuth, async (req, res) => {
  const accountId = req.session.account_id;

  const [projects, scripts, keys, revoked, loadsToday, loginsToday] = await Promise.all([
    supabase.from("projects").select("id", { count: "exact", head: true }).eq("owner_account_id", accountId),
    supabase.from("scripts").select("id, projects!inner(owner_account_id)", { count: "exact", head: true }).eq("projects.owner_account_id", accountId),
    supabase.from("keys").select("id", { count: "exact", head: true }).eq("owner_account_id", accountId),
    supabase.from("keys").select("id", { count: "exact", head: true }).eq("owner_account_id", accountId).eq("revoked", true),
    supabase.from("access_log").select("id", { count: "exact", head: true }).eq("owner_account_id", accountId).eq("event", "load").gte("created_at", new Date(Date.now() - 86400000).toISOString()),
    supabase.from("access_log").select("id", { count: "exact", head: true }).eq("owner_account_id", accountId).eq("event", "login").gte("created_at", new Date(Date.now() - 86400000).toISOString()),
  ]);

  const limits = await getPlanLimits(req.session.plan);

  res.json({
    ok: true,
    stats: {
      projects: projects.count || 0,
      scripts: scripts.count || 0,
      keys: keys.count || 0,
      active_keys: (keys.count || 0) - (revoked.count || 0),
      revoked_keys: revoked.count || 0,
      loads_24h: loadsToday.count || 0,
      logins_24h: loginsToday.count || 0,
    },
    limits,
  });
});

// ============================================================
// PROJECTS (scoped to account)
// ============================================================
app.get("/api/projects", requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from("projects")
    .select("id, name, slug, note, status, created_at")
    .eq("owner_account_id", req.session.account_id)
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ ok: false, error: "Server error" });

  // Add script + key counts per project
  const withCounts = await Promise.all(
    (data || []).map(async (p) => {
      const [scr, kys] = await Promise.all([
        supabase.from("scripts").select("id", { count: "exact", head: true }).eq("project_id", p.id),
        supabase.from("keys").select("id", { count: "exact", head: true }).eq("project_id", p.id),
      ]);
      return { ...p, script_count: scr.count || 0, key_count: kys.count || 0 };
    })
  );

  res.json({ ok: true, projects: withCounts });
});

app.post("/api/projects", requireAuth, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const note = String(req.body?.note || "").trim();
  if (!name) return res.status(400).json({ ok: false, error: "Project name is required" });

  const limits = await getPlanLimits(req.session.plan);
  const { count } = await supabase.from("projects").select("id", { count: "exact", head: true }).eq("owner_account_id", req.session.account_id);
  if ((count || 0) >= limits.max_projects) {
    return res.status(403).json({ ok: false, error: `Project limit reached (${limits.max_projects}). Upgrade your plan.` });
  }

  const { data, error } = await supabase
    .from("projects")
    .insert({ owner_account_id: req.session.account_id, name, note, slug: makeSlug(name) })
    .select("id, name, slug, note, status, created_at")
    .single();

  if (error) return res.status(500).json({ ok: false, error: "Could not create project" });
  res.json({ ok: true, project: data });
});

app.patch("/api/projects/:id", requireAuth, async (req, res) => {
  const patch = {};
  if (typeof req.body?.name === "string") patch.name = req.body.name.trim();
  if (typeof req.body?.note === "string") patch.note = req.body.note;
  if (req.body?.status === "active" || req.body?.status === "paused") patch.status = req.body.status;

  const { data, error } = await supabase
    .from("projects")
    .update(patch)
    .eq("id", req.params.id)
    .eq("owner_account_id", req.session.account_id)
    .select()
    .single();

  if (error) return res.status(500).json({ ok: false, error: "Could not update project" });
  res.json({ ok: true, project: data });
});

app.delete("/api/projects/:id", requireAuth, async (req, res) => {
  const { error } = await supabase
    .from("projects")
    .delete()
    .eq("id", req.params.id)
    .eq("owner_account_id", req.session.account_id);
  if (error) return res.status(500).json({ ok: false, error: "Could not delete" });
  res.json({ ok: true });
});

// ============================================================
// SCRIPTS (nested under project, scoped via project ownership)
// ============================================================
app.get("/api/projects/:pid/scripts", requireAuth, async (req, res) => {
  // Verify project ownership
  const { data: proj } = await supabase
    .from("projects").select("id").eq("id", req.params.pid).eq("owner_account_id", req.session.account_id).maybeSingle();
  if (!proj) return res.status(404).json({ ok: false, error: "Project not found" });

  const { data, error } = await supabase
    .from("scripts")
    .select("id, name, description, slug, protection, key_mode, size_bytes, version, enabled, created_at, updated_at")
    .eq("project_id", req.params.pid)
    .order("created_at", { ascending: false });

  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  res.json({ ok: true, scripts: data });
});

app.post("/api/projects/:pid/scripts", requireAuth, async (req, res) => {
  const { data: proj } = await supabase
    .from("projects").select("id").eq("id", req.params.pid).eq("owner_account_id", req.session.account_id).maybeSingle();
  if (!proj) return res.status(404).json({ ok: false, error: "Project not found" });

  const limits = await getPlanLimits(req.session.plan);
  const { count } = await supabase.from("scripts").select("id", { count: "exact", head: true }).eq("project_id", req.params.pid);
  if ((count || 0) >= limits.max_scripts_per_project) {
    return res.status(403).json({ ok: false, error: `Script limit reached (${limits.max_scripts_per_project} per project).` });
  }

  const body = req.body || {};
  const name = String(body.name || "").trim();
  if (!name) return res.status(400).json({ ok: false, error: "Script name is required" });
  const source = String(body.source || "");

  const insert = {
    project_id: req.params.pid,
    name,
    slug: makeSlug(name),
    description: String(body.description || ""),
    protection: ["none", "luraph", "wynfuscate"].includes(body.protection) ? body.protection : "none",
    key_mode: body.key_mode === "keyless" ? "keyless" : "keyed",
    source,
    size_bytes: Buffer.byteLength(source, "utf8"),
    enabled: body.enabled !== false,
    syntax_check: body.syntax_check !== false,
    fast_mode: !!body.fast_mode,
    same_device: body.same_device !== false,
    silent_mode: body.silent_mode !== false,
    player_ui: ["no_gui", "loading", "key_gui", "custom"].includes(body.player_ui) ? body.player_ui : "no_gui",
    game_id: body.game_id ? String(body.game_id) : null,
  };

  const { data, error } = await supabase.from("scripts").insert(insert).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not create script" });
  res.json({ ok: true, script: data });
});

app.patch("/api/scripts/:id", requireAuth, async (req, res) => {
  // Verify ownership via project join
  const { data: existing } = await supabase
    .from("scripts")
    .select("id, project_id, projects!inner(owner_account_id)")
    .eq("id", req.params.id)
    .maybeSingle();
  if (!existing || existing.projects.owner_account_id !== req.session.account_id) {
    return res.status(404).json({ ok: false, error: "Script not found" });
  }

  const body = req.body || {};
  const patch = { updated_at: new Date().toISOString() };
  if (typeof body.name === "string") patch.name = body.name.trim();
  if (typeof body.description === "string") patch.description = body.description;
  if (["none", "luraph", "wynfuscate"].includes(body.protection)) patch.protection = body.protection;
  if (body.key_mode === "keyed" || body.key_mode === "keyless") patch.key_mode = body.key_mode;
  if (typeof body.source === "string") { patch.source = body.source; patch.size_bytes = Buffer.byteLength(body.source, "utf8"); patch.version = (existing.version || 1) + 1; }
  if (typeof body.enabled === "boolean") patch.enabled = body.enabled;
  if (typeof body.syntax_check === "boolean") patch.syntax_check = body.syntax_check;
  if (typeof body.fast_mode === "boolean") patch.fast_mode = body.fast_mode;
  if (typeof body.same_device === "boolean") patch.same_device = body.same_device;
  if (typeof body.silent_mode === "boolean") patch.silent_mode = body.silent_mode;
  if (["no_gui", "loading", "key_gui", "custom"].includes(body.player_ui)) patch.player_ui = body.player_ui;
  if (typeof body.game_id === "string") patch.game_id = body.game_id;

  const { data, error } = await supabase.from("scripts").update(patch).eq("id", req.params.id).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not update script" });
  res.json({ ok: true, script: data });
});

app.delete("/api/scripts/:id", requireAuth, async (req, res) => {
  const { data: existing } = await supabase
    .from("scripts").select("id, projects!inner(owner_account_id)").eq("id", req.params.id).maybeSingle();
  if (!existing || existing.projects.owner_account_id !== req.session.account_id) {
    return res.status(404).json({ ok: false, error: "Script not found" });
  }
  await supabase.from("scripts").delete().eq("id", req.params.id);
  res.json({ ok: true });
});

// ============================================================
// KEYS (scoped to account)
// ============================================================
app.get("/api/keys", requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from("keys")
    .select("id, key, label, revoked, project_id, created_at, last_used_at")
    .eq("owner_account_id", req.session.account_id)
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  res.json({ ok: true, keys: data });
});

app.post("/api/keys", requireAuth, async (req, res) => {
  const limits = await getPlanLimits(req.session.plan);
  const { count } = await supabase.from("keys").select("id", { count: "exact", head: true }).eq("owner_account_id", req.session.account_id);
  if ((count || 0) >= limits.max_keys) {
    return res.status(403).json({ ok: false, error: `Key limit reached (${limits.max_keys}).` });
  }

  const body = req.body || {};
  const key = makeKey(body.prefix || "KF");

  const { data, error } = await supabase.from("keys").insert({
    owner_account_id: req.session.account_id,
    project_id: body.project_id || null,
    key,
    label: String(body.label || "").trim() || null,
  }).select().single();

  if (error) return res.status(500).json({ ok: false, error: "Could not create key" });
  res.json({ ok: true, key: data });
});

app.patch("/api/keys/:id", requireAuth, async (req, res) => {
  const patch = {};
  if (typeof req.body?.revoked === "boolean") patch.revoked = req.body.revoked;
  if (typeof req.body?.label === "string") patch.label = req.body.label.trim();

  const { data, error } = await supabase
    .from("keys").update(patch).eq("id", req.params.id).eq("owner_account_id", req.session.account_id).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not update key" });
  res.json({ ok: true, key: data });
});

app.delete("/api/keys/:id", requireAuth, async (req, res) => {
  const { error } = await supabase
    .from("keys").delete().eq("id", req.params.id).eq("owner_account_id", req.session.account_id);
  if (error) return res.status(500).json({ ok: false, error: "Could not delete" });
  res.json({ ok: true });
});

// ============================================================
// OWNER: manage all accounts (you only)
// ============================================================
app.get("/api/accounts", requireAuth, requireOwner, async (req, res) => {
  const { data, error } = await supabase
    .from("accounts").select("id, name, api_key, plan, role, created_at, last_login")
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  res.json({ ok: true, accounts: data });
});

app.post("/api/accounts", requireAuth, requireOwner, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const plan = ["free", "creator", "scale"].includes(req.body?.plan) ? req.body.plan : "free";
  if (!name) return res.status(400).json({ ok: false, error: "Name is required" });

  const apiKey = makeKey("SL");
  const { data, error } = await supabase
    .from("accounts").insert({ name, api_key: apiKey, plan, role: "user" }).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not create account" });
  res.json({ ok: true, account: data });
});

app.delete("/api/accounts/:id", requireAuth, requireOwner, async (req, res) => {
  const { error } = await supabase.from("accounts").delete().eq("id", req.params.id);
  if (error) return res.status(500).json({ ok: false, error: "Could not delete" });
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("Solaries multi-tenant server running on port " + PORT);
});
