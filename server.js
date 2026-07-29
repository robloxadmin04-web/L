// server.js - Solaries Phase 6 (Discord Bot D2.1 - detailed errors)
// Adds on top of D1: /panel command + Get Key / Get Script / Reset HWID buttons
// Bot only starts if DISCORD_BOT_TOKEN env var is set (safe fallback).

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || "https://solaries.onrender.com";

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false },
});

app.use(express.json({ limit: "2mb" }));
app.set("trust proxy", true);
app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// Sessions
// ============================================================
const sessions = new Map();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

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
  if (Date.now() > s.expires_at) { sessions.delete(token); return null; }
  return s;
}

function requireAuth(req, res, next) {
  const token = req.header("x-session-token");
  const session = token ? getSession(token) : null;
  if (!session) return res.status(401).json({ ok: false, error: "Not signed in" });
  req.session = session;
  next();
}

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
  for (let i = 0; i < 4; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
  return out;
}
function makeKey(prefix) {
  const safe = (prefix || "KF").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 6) || "KF";
  return `${safe}-${randomBlock()}-${randomBlock()}-${randomBlock()}`;
}
function makeSlug(name) {
  const base = String(name || "item").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "item";
  return base + "-" + randomBlock().toLowerCase();
}
async function getPlanLimits(plan) {
  const { data } = await supabase.from("plan_limits").select("*").eq("plan", plan).maybeSingle();
  return data || { max_projects: 1, max_scripts_per_project: 3, max_keys: 50, max_obfuscations_per_month: 20 };
}
function getClientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket?.remoteAddress || "";
}
function getHwid(req) {
  return String(req.headers["x-hwid"] || req.query.hwid || "").trim();
}

// ============================================================
// AUTH
// ============================================================
app.post("/api/signin", async (req, res) => {
  const apiKey = (req.body?.key || "").trim();
  if (!apiKey) return res.status(400).json({ ok: false, error: "Missing key" });

  const { data: account, error } = await supabase
    .from("accounts").select("id, name, api_key, plan, role")
    .eq("api_key", apiKey).maybeSingle();

  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  if (!account) return res.json({ ok: false, error: "Invalid API key" });

  await supabase.from("accounts").update({ last_login: new Date().toISOString() }).eq("id", account.id);
  await supabase.from("access_log").insert({ owner_account_id: account.id, event: "login" });

  const token = createSession(account);
  res.json({ ok: true, token, account: { id: account.id, name: account.name, plan: account.plan, role: account.role } });
});

app.post("/api/signout", requireAuth, (req, res) => {
  sessions.delete(req.header("x-session-token"));
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, async (req, res) => {
  const limits = await getPlanLimits(req.session.plan);
  res.json({ ok: true, account: req.session, limits });
});

// ============================================================
// PUBLIC LOADER - with HWID, expiry, and block/allow checks
// ============================================================
app.get("/v1/load/:script_slug", async (req, res) => {
  res.type("text/plain");
  const scriptSlug = req.params.script_slug;
  const key = (req.query.key || "").trim();
  const hwid = getHwid(req);
  const ip = getClientIp(req);

  async function block(reason, code, keyId, projectId, scriptId) {
    await supabase.from("access_log").insert({
      owner_account_id: null,
      key_id: keyId || null,
      project_id: projectId || null,
      script_id: scriptId || null,
      event: "blocked",
      reason,
      hwid: hwid || null,
      ip: ip || null,
    });
    return res.status(code).send("-- " + reason);
  }

  const { data: script } = await supabase
    .from("scripts")
    .select("id, project_id, source, key_mode, enabled, projects!inner(id, status, whitelist_only, owner_account_id)")
    .eq("slug", scriptSlug)
    .maybeSingle();

  if (!script) return res.status(404).send("-- script not found");
  if (!script.enabled) return block("script disabled", 403, null, script.project_id, script.id);
  if (script.projects.status === "paused") return block("project paused", 403, null, script.project_id, script.id);

  const projectId = script.project_id;
  const accountId = script.projects.owner_account_id;

  if (hwid || ip) {
    const orParts = [];
    if (hwid) orParts.push(`and(entry_type.eq.hwid,value.eq.${hwid})`);
    if (ip) orParts.push(`and(entry_type.eq.ip,value.eq.${ip})`);
    if (orParts.length) {
      const { data: blocked } = await supabase
        .from("blocklist")
        .select("id")
        .eq("project_id", projectId)
        .or(orParts.join(","))
        .limit(1);
      if (blocked && blocked.length) return block("blocked device or ip", 403, null, projectId, script.id);
    }
  }

  if (script.projects.whitelist_only && hwid) {
    const { data: allowed } = await supabase
      .from("allowlist")
      .select("id")
      .eq("project_id", projectId)
      .eq("entry_type", "hwid")
      .eq("value", hwid)
      .maybeSingle();
    if (!allowed) return block("device not on allowlist", 403, null, projectId, script.id);
  }

  if (script.key_mode === "keyed") {
    if (!key) return block("missing key", 401, null, projectId, script.id);

    const { data: keyRow } = await supabase
      .from("keys")
      .select("id, revoked, project_id, owner_account_id, hwid, hwid_locked, expires_at")
      .eq("key", key)
      .maybeSingle();

    if (!keyRow) return block("invalid key", 403, null, projectId, script.id);
    if (keyRow.revoked) return block("revoked key", 403, keyRow.id, projectId, script.id);

    const { data: keyBlocked } = await supabase
      .from("blocklist")
      .select("id")
      .eq("project_id", projectId)
      .eq("entry_type", "key")
      .eq("value", key)
      .maybeSingle();
    if (keyBlocked) return block("key blocked", 403, keyRow.id, projectId, script.id);

    if (keyRow.project_id && keyRow.project_id !== projectId) {
      return block("key not valid for this script", 403, keyRow.id, projectId, script.id);
    }

    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
      return block("key expired", 403, keyRow.id, projectId, script.id);
    }

    if (keyRow.hwid_locked) {
      if (!hwid) return block("missing hwid header", 401, keyRow.id, projectId, script.id);
      if (!keyRow.hwid) {
        await supabase.from("keys").update({ hwid: hwid }).eq("id", keyRow.id);
      } else if (keyRow.hwid !== hwid) {
        return block("key locked to a different device", 403, keyRow.id, projectId, script.id);
      }
    }

    await supabase.from("keys").update({ last_used_at: new Date().toISOString() }).eq("id", keyRow.id);
    await supabase.from("access_log").insert({
      owner_account_id: keyRow.owner_account_id,
      key_id: keyRow.id, project_id: projectId, script_id: script.id,
      event: "load", hwid: hwid || null, ip: ip || null,
    });
  } else {
    await supabase.from("access_log").insert({
      owner_account_id: accountId,
      project_id: projectId, script_id: script.id,
      event: "load", hwid: hwid || null, ip: ip || null,
    });
  }

  return res.status(200).send(script.source || "-- empty script");
});

// ============================================================
// STATS
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
// ANALYTICS
// ============================================================
app.get("/api/analytics", requireAuth, async (req, res) => {
  const accountId = req.session.account_id;
  const now = Date.now();
  const day = 86400000;
  const since30d = new Date(now - 30 * day).toISOString();
  const since7d = new Date(now - 7 * day).toISOString();
  const since24h = new Date(now - day).toISOString();

  try {
    const { data: loads } = await supabase
      .from("access_log")
      .select("id, project_id, script_id, key_id, created_at")
      .eq("owner_account_id", accountId)
      .eq("event", "load")
      .gte("created_at", since30d)
      .order("created_at", { ascending: false }).limit(5000);
    const loadRows = loads || [];

    const byDay = new Map();
    for (let i = 29; i >= 0; i--) {
      const d = new Date(now - i * day);
      byDay.set(d.toISOString().slice(0, 10), 0);
    }
    loadRows.forEach((r) => {
      const label = String(r.created_at).slice(0, 10);
      if (byDay.has(label)) byDay.set(label, byDay.get(label) + 1);
    });
    const series = Array.from(byDay.entries()).map(([date, count]) => ({ date, count }));

    const loads7d = loadRows.filter((r) => r.created_at >= since7d).length;
    const loads30d = loadRows.length;
    const uniqueKeys24h = new Set(loadRows.filter((r) => r.created_at >= since24h && r.key_id).map((r) => r.key_id)).size;

    const scriptCounts = new Map();
    loadRows.forEach((r) => { if (r.script_id) scriptCounts.set(r.script_id, (scriptCounts.get(r.script_id) || 0) + 1); });
    const topScriptIds = Array.from(scriptCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([id]) => id);

    let topScripts = [];
    if (topScriptIds.length > 0) {
      const { data: scriptRows } = await supabase
        .from("scripts")
        .select("id, name, slug, project_id, projects!inner(name, owner_account_id)")
        .in("id", topScriptIds).eq("projects.owner_account_id", accountId);
      topScripts = (scriptRows || []).map((s) => ({
        id: s.id, name: s.name, slug: s.slug,
        project_name: s.projects?.name || "(deleted)",
        loads: scriptCounts.get(s.id) || 0,
      })).sort((a, b) => b.loads - a.loads);
    }

    const projectCounts = new Map();
    loadRows.forEach((r) => { if (r.project_id) projectCounts.set(r.project_id, (projectCounts.get(r.project_id) || 0) + 1); });
    const topProjectEntry = Array.from(projectCounts.entries()).sort((a, b) => b[1] - a[1])[0];
    let topProject = null;
    if (topProjectEntry) {
      const { data: p } = await supabase.from("projects").select("id, name").eq("id", topProjectEntry[0]).eq("owner_account_id", accountId).maybeSingle();
      if (p) topProject = { name: p.name, loads: topProjectEntry[1] };
    }

    const { data: recentRaw } = await supabase
      .from("access_log").select("id, event, key_id, project_id, script_id, created_at")
      .eq("owner_account_id", accountId).order("created_at", { ascending: false }).limit(20);
    const recent = recentRaw || [];
    const projIds = [...new Set(recent.map((r) => r.project_id).filter(Boolean))];
    const scriptIds = [...new Set(recent.map((r) => r.script_id).filter(Boolean))];
    let projMap = {}, scriptMap = {};
    if (projIds.length) {
      const { data } = await supabase.from("projects").select("id, name").in("id", projIds);
      (data || []).forEach((p) => (projMap[p.id] = p.name));
    }
    if (scriptIds.length) {
      const { data } = await supabase.from("scripts").select("id, name").in("id", scriptIds);
      (data || []).forEach((s) => (scriptMap[s.id] = s.name));
    }
    const activity = recent.map((r) => ({
      id: r.id, event: r.event, created_at: r.created_at,
      project_name: r.project_id ? (projMap[r.project_id] || "(deleted)") : null,
      script_name: r.script_id ? (scriptMap[r.script_id] || "(deleted)") : null,
    }));

    res.json({
      ok: true,
      analytics: {
        loads_7d: loads7d, loads_30d: loads30d,
        unique_keys_24h: uniqueKeys24h,
        top_project: topProject, series,
        top_scripts: topScripts, activity,
      },
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ============================================================
// PROJECTS
// ============================================================
app.get("/api/projects", requireAuth, async (req, res) => {
  const { data, error } = await supabase.from("projects")
    .select("id, name, slug, note, status, whitelist_only, created_at")
    .eq("owner_account_id", req.session.account_id).order("created_at", { ascending: false });
  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  const withCounts = await Promise.all((data || []).map(async (p) => {
    const [scr, kys] = await Promise.all([
      supabase.from("scripts").select("id", { count: "exact", head: true }).eq("project_id", p.id),
      supabase.from("keys").select("id", { count: "exact", head: true }).eq("project_id", p.id),
    ]);
    return { ...p, script_count: scr.count || 0, key_count: kys.count || 0 };
  }));
  res.json({ ok: true, projects: withCounts });
});

app.post("/api/projects", requireAuth, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const note = String(req.body?.note || "").trim();
  if (!name) return res.status(400).json({ ok: false, error: "Project name is required" });
  const limits = await getPlanLimits(req.session.plan);
  const { count } = await supabase.from("projects").select("id", { count: "exact", head: true }).eq("owner_account_id", req.session.account_id);
  if ((count || 0) >= limits.max_projects) {
    return res.status(403).json({ ok: false, error: `Project limit reached (${limits.max_projects}).` });
  }
  const { data, error } = await supabase.from("projects")
    .insert({ owner_account_id: req.session.account_id, name, note, slug: makeSlug(name) })
    .select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not create project" });
  res.json({ ok: true, project: data });
});

app.patch("/api/projects/:id", requireAuth, async (req, res) => {
  const patch = {};
  if (typeof req.body?.name === "string") patch.name = req.body.name.trim();
  if (typeof req.body?.note === "string") patch.note = req.body.note;
  if (req.body?.status === "active" || req.body?.status === "paused") patch.status = req.body.status;
  if (typeof req.body?.whitelist_only === "boolean") patch.whitelist_only = req.body.whitelist_only;
  const { data, error } = await supabase.from("projects").update(patch)
    .eq("id", req.params.id).eq("owner_account_id", req.session.account_id).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not update project" });
  res.json({ ok: true, project: data });
});

app.delete("/api/projects/:id", requireAuth, async (req, res) => {
  const { error } = await supabase.from("projects").delete()
    .eq("id", req.params.id).eq("owner_account_id", req.session.account_id);
  if (error) return res.status(500).json({ ok: false, error: "Could not delete" });
  res.json({ ok: true });
});

// ============================================================
// SCRIPTS + version snapshots
// ============================================================
async function ownsProject(pid, accountId) {
  const { data } = await supabase.from("projects").select("id").eq("id", pid).eq("owner_account_id", accountId).maybeSingle();
  return !!data;
}
async function loadScriptOwned(scriptId, accountId) {
  const { data } = await supabase.from("scripts")
    .select("id, project_id, source, version, projects!inner(owner_account_id)")
    .eq("id", scriptId).maybeSingle();
  if (!data || data.projects.owner_account_id !== accountId) return null;
  return data;
}

app.get("/api/projects/:pid/scripts", requireAuth, async (req, res) => {
  if (!await ownsProject(req.params.pid, req.session.account_id))
    return res.status(404).json({ ok: false, error: "Project not found" });
  const { data, error } = await supabase.from("scripts")
    .select("id, name, description, slug, protection, key_mode, size_bytes, version, enabled, created_at, updated_at")
    .eq("project_id", req.params.pid).order("created_at", { ascending: false });
  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  res.json({ ok: true, scripts: data });
});

app.post("/api/projects/:pid/scripts", requireAuth, async (req, res) => {
  if (!await ownsProject(req.params.pid, req.session.account_id))
    return res.status(404).json({ ok: false, error: "Project not found" });
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
    project_id: req.params.pid, name, slug: makeSlug(name),
    description: String(body.description || ""),
    protection: ["none", "luraph", "wynfuscate"].includes(body.protection) ? body.protection : "none",
    key_mode: body.key_mode === "keyless" ? "keyless" : "keyed",
    source, size_bytes: Buffer.byteLength(source, "utf8"),
    enabled: body.enabled !== false, syntax_check: body.syntax_check !== false,
    fast_mode: !!body.fast_mode, same_device: body.same_device !== false,
    silent_mode: body.silent_mode !== false,
    player_ui: ["no_gui", "loading", "key_gui", "custom"].includes(body.player_ui) ? body.player_ui : "no_gui",
    game_id: body.game_id ? String(body.game_id) : null,
  };
  const { data, error } = await supabase.from("scripts").insert(insert).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not create script" });
  await supabase.from("script_versions").insert({
    script_id: data.id, version: 1, source: source,
    size_bytes: Buffer.byteLength(source, "utf8"),
    note: "Initial",
  });
  res.json({ ok: true, script: data });
});

app.patch("/api/scripts/:id", requireAuth, async (req, res) => {
  const existing = await loadScriptOwned(req.params.id, req.session.account_id);
  if (!existing) return res.status(404).json({ ok: false, error: "Script not found" });
  const body = req.body || {};
  const patch = { updated_at: new Date().toISOString() };
  let bumped = false;
  let newVersion = existing.version || 1;
  if (typeof body.name === "string") patch.name = body.name.trim();
  if (typeof body.description === "string") patch.description = body.description;
  if (["none", "luraph", "wynfuscate"].includes(body.protection)) patch.protection = body.protection;
  if (body.key_mode === "keyed" || body.key_mode === "keyless") patch.key_mode = body.key_mode;
  if (typeof body.source === "string" && body.source !== existing.source) {
    patch.source = body.source;
    patch.size_bytes = Buffer.byteLength(body.source, "utf8");
    newVersion = (existing.version || 1) + 1;
    patch.version = newVersion;
    bumped = true;
  }
  if (typeof body.enabled === "boolean") patch.enabled = body.enabled;
  if (typeof body.syntax_check === "boolean") patch.syntax_check = body.syntax_check;
  if (typeof body.fast_mode === "boolean") patch.fast_mode = body.fast_mode;
  if (typeof body.same_device === "boolean") patch.same_device = body.same_device;
  if (typeof body.silent_mode === "boolean") patch.silent_mode = body.silent_mode;
  if (["no_gui", "loading", "key_gui", "custom"].includes(body.player_ui)) patch.player_ui = body.player_ui;
  if (typeof body.game_id === "string") patch.game_id = body.game_id;

  const { data, error } = await supabase.from("scripts").update(patch).eq("id", req.params.id).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not update script" });

  if (bumped) {
    await supabase.from("script_versions").insert({
      script_id: data.id, version: newVersion,
      source: body.source, size_bytes: Buffer.byteLength(body.source, "utf8"),
      note: body.version_note || null,
    });
  }
  res.json({ ok: true, script: data });
});

app.delete("/api/scripts/:id", requireAuth, async (req, res) => {
  const existing = await loadScriptOwned(req.params.id, req.session.account_id);
  if (!existing) return res.status(404).json({ ok: false, error: "Script not found" });
  await supabase.from("scripts").delete().eq("id", req.params.id);
  res.json({ ok: true });
});

app.get("/api/scripts/:id/versions", requireAuth, async (req, res) => {
  const existing = await loadScriptOwned(req.params.id, req.session.account_id);
  if (!existing) return res.status(404).json({ ok: false, error: "Script not found" });
  const { data } = await supabase.from("script_versions")
    .select("id, version, size_bytes, note, created_at")
    .eq("script_id", req.params.id).order("version", { ascending: false });
  res.json({ ok: true, versions: data || [] });
});

app.get("/api/scripts/:id/versions/:v", requireAuth, async (req, res) => {
  const existing = await loadScriptOwned(req.params.id, req.session.account_id);
  if (!existing) return res.status(404).json({ ok: false, error: "Script not found" });
  const { data } = await supabase.from("script_versions")
    .select("id, version, source, size_bytes, note, created_at")
    .eq("script_id", req.params.id).eq("version", parseInt(req.params.v, 10)).maybeSingle();
  if (!data) return res.status(404).json({ ok: false, error: "Version not found" });
  res.json({ ok: true, version: data });
});

app.post("/api/scripts/:id/restore/:v", requireAuth, async (req, res) => {
  const existing = await loadScriptOwned(req.params.id, req.session.account_id);
  if (!existing) return res.status(404).json({ ok: false, error: "Script not found" });
  const { data: v } = await supabase.from("script_versions")
    .select("source").eq("script_id", req.params.id).eq("version", parseInt(req.params.v, 10)).maybeSingle();
  if (!v) return res.status(404).json({ ok: false, error: "Version not found" });
  const newVersion = (existing.version || 1) + 1;
  const { data: updated, error } = await supabase.from("scripts")
    .update({ source: v.source, size_bytes: Buffer.byteLength(v.source, "utf8"), version: newVersion, updated_at: new Date().toISOString() })
    .eq("id", req.params.id).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not restore" });
  await supabase.from("script_versions").insert({
    script_id: req.params.id, version: newVersion,
    source: v.source, size_bytes: Buffer.byteLength(v.source, "utf8"),
    note: "Restored from v" + req.params.v,
  });
  res.json({ ok: true, script: updated });
});

// ============================================================
// KEYS - with HWID + expiry management
// ============================================================
app.get("/api/keys", requireAuth, async (req, res) => {
  const { data, error } = await supabase.from("keys")
    .select("id, key, label, revoked, project_id, hwid, hwid_locked, expires_at, created_at, last_used_at")
    .eq("owner_account_id", req.session.account_id).order("created_at", { ascending: false });
  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  res.json({ ok: true, keys: data });
});

app.post("/api/keys", requireAuth, async (req, res) => {
  const limits = await getPlanLimits(req.session.plan);
  const { count } = await supabase.from("keys").select("id", { count: "exact", head: true }).eq("owner_account_id", req.session.account_id);
  if ((count || 0) >= limits.max_keys) return res.status(403).json({ ok: false, error: `Key limit reached (${limits.max_keys}).` });

  const body = req.body || {};
  const key = makeKey(body.prefix || "KF");
  const insert = {
    owner_account_id: req.session.account_id,
    project_id: body.project_id || null,
    key,
    label: String(body.label || "").trim() || null,
    hwid_locked: !!body.hwid_locked,
  };
  if (body.expires_in_days) {
    const days = parseInt(body.expires_in_days, 10);
    if (days > 0) insert.expires_at = new Date(Date.now() + days * 86400000).toISOString();
  } else if (body.expires_at) {
    insert.expires_at = body.expires_at;
  }
  const { data, error } = await supabase.from("keys").insert(insert).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not create key" });
  res.json({ ok: true, key: data });
});

app.patch("/api/keys/:id", requireAuth, async (req, res) => {
  const patch = {};
  const body = req.body || {};
  if (typeof body.revoked === "boolean") patch.revoked = body.revoked;
  if (typeof body.label === "string") patch.label = body.label.trim();
  if (typeof body.hwid_locked === "boolean") patch.hwid_locked = body.hwid_locked;
  if (body.expires_at === null) patch.expires_at = null;
  else if (typeof body.expires_at === "string") patch.expires_at = body.expires_at;
  const { data, error } = await supabase.from("keys").update(patch)
    .eq("id", req.params.id).eq("owner_account_id", req.session.account_id).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not update key" });
  res.json({ ok: true, key: data });
});

app.post("/api/keys/:id/reset-hwid", requireAuth, async (req, res) => {
  const { data, error } = await supabase.from("keys").update({ hwid: null })
    .eq("id", req.params.id).eq("owner_account_id", req.session.account_id).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not reset HWID" });
  res.json({ ok: true, key: data });
});

app.delete("/api/keys/:id", requireAuth, async (req, res) => {
  const { error } = await supabase.from("keys").delete()
    .eq("id", req.params.id).eq("owner_account_id", req.session.account_id);
  if (error) return res.status(500).json({ ok: false, error: "Could not delete" });
  res.json({ ok: true });
});

// ============================================================
// BLOCKLIST / ALLOWLIST per project
// ============================================================
app.get("/api/projects/:pid/blocklist", requireAuth, async (req, res) => {
  if (!await ownsProject(req.params.pid, req.session.account_id))
    return res.status(404).json({ ok: false, error: "Project not found" });
  const { data } = await supabase.from("blocklist")
    .select("id, entry_type, value, reason, created_at")
    .eq("project_id", req.params.pid).order("created_at", { ascending: false });
  res.json({ ok: true, entries: data || [] });
});

app.post("/api/projects/:pid/blocklist", requireAuth, async (req, res) => {
  if (!await ownsProject(req.params.pid, req.session.account_id))
    return res.status(404).json({ ok: false, error: "Project not found" });
  const body = req.body || {};
  const entryType = ["hwid", "ip", "key"].includes(body.entry_type) ? body.entry_type : null;
  const value = String(body.value || "").trim();
  if (!entryType || !value) return res.status(400).json({ ok: false, error: "entry_type and value are required" });
  const { data, error } = await supabase.from("blocklist").insert({
    owner_account_id: req.session.account_id, project_id: req.params.pid,
    entry_type: entryType, value, reason: body.reason || null,
  }).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not add - value may already be blocked" });
  res.json({ ok: true, entry: data });
});

app.delete("/api/blocklist/:id", requireAuth, async (req, res) => {
  const { error } = await supabase.from("blocklist").delete()
    .eq("id", req.params.id).eq("owner_account_id", req.session.account_id);
  if (error) return res.status(500).json({ ok: false, error: "Could not remove" });
  res.json({ ok: true });
});

app.get("/api/projects/:pid/allowlist", requireAuth, async (req, res) => {
  if (!await ownsProject(req.params.pid, req.session.account_id))
    return res.status(404).json({ ok: false, error: "Project not found" });
  const { data } = await supabase.from("allowlist")
    .select("id, entry_type, value, note, created_at")
    .eq("project_id", req.params.pid).order("created_at", { ascending: false });
  res.json({ ok: true, entries: data || [] });
});

app.post("/api/projects/:pid/allowlist", requireAuth, async (req, res) => {
  if (!await ownsProject(req.params.pid, req.session.account_id))
    return res.status(404).json({ ok: false, error: "Project not found" });
  const body = req.body || {};
  const entryType = ["hwid", "key"].includes(body.entry_type) ? body.entry_type : null;
  const value = String(body.value || "").trim();
  if (!entryType || !value) return res.status(400).json({ ok: false, error: "entry_type and value are required" });
  const { data, error } = await supabase.from("allowlist").insert({
    owner_account_id: req.session.account_id, project_id: req.params.pid,
    entry_type: entryType, value, note: body.note || null,
  }).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not add - value may already be allowed" });
  res.json({ ok: true, entry: data });
});

app.delete("/api/allowlist/:id", requireAuth, async (req, res) => {
  const { error } = await supabase.from("allowlist").delete()
    .eq("id", req.params.id).eq("owner_account_id", req.session.account_id);
  if (error) return res.status(500).json({ ok: false, error: "Could not remove" });
  res.json({ ok: true });
});

// ============================================================
// OWNER: accounts
// ============================================================
app.get("/api/accounts", requireAuth, requireOwner, async (req, res) => {
  const { data, error } = await supabase.from("accounts")
    .select("id, name, api_key, plan, role, created_at, last_login")
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  res.json({ ok: true, accounts: data });
});

app.post("/api/accounts", requireAuth, requireOwner, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const plan = ["free", "creator", "scale"].includes(req.body?.plan) ? req.body.plan : "free";
  if (!name) return res.status(400).json({ ok: false, error: "Name is required" });
  const apiKey = makeKey("SL");
  const { data, error } = await supabase.from("accounts")
    .insert({ name, api_key: apiKey, plan, role: "user" }).select().single();
  if (error) return res.status(500).json({ ok: false, error: "Could not create account" });
  res.json({ ok: true, account: data });
});

app.delete("/api/accounts/:id", requireAuth, requireOwner, async (req, res) => {
  const { error } = await supabase.from("accounts").delete().eq("id", req.params.id);
  if (error) return res.status(500).json({ ok: false, error: "Could not delete" });
  res.json({ ok: true });
});

// ============================================================
// DISCORD - status endpoint (for dashboard UI later)
// ============================================================
let botStatus = {
  online: false,
  username: null,
  guild_count: 0,
  started_at: null,
  last_error: null,
};

app.get("/api/discord/status", requireAuth, (req, res) => {
  res.json({ ok: true, status: botStatus });
});

app.get("/api/discord/link", requireAuth, async (req, res) => {
  const { data } = await supabase.from("discord_users")
    .select("discord_id, discord_username, linked_at")
    .eq("account_id", req.session.account_id).maybeSingle();
  res.json({ ok: true, linked: data || null });
});

app.delete("/api/discord/link", requireAuth, async (req, res) => {
  await supabase.from("discord_users").delete().eq("account_id", req.session.account_id);
  res.json({ ok: true });
});

app.get("/api/discord/panels", requireAuth, async (req, res) => {
  const { data } = await supabase.from("discord_panels")
    .select("id, script_id, guild_id, channel_id, message_id, created_at, scripts(name, slug)")
    .eq("account_id", req.session.account_id).order("created_at", { ascending: false });
  res.json({ ok: true, panels: data || [] });
});

app.delete("/api/discord/panels/:id", requireAuth, async (req, res) => {
  const { error } = await supabase.from("discord_panels").delete()
    .eq("id", req.params.id).eq("account_id", req.session.account_id);
  if (error) return res.status(500).json({ ok: false, error: "Could not delete" });
  res.json({ ok: true });
});

// ============================================================
// Health check + keep-alive
// ============================================================
app.get("/healthz", (req, res) => {
  res.json({ ok: true, ts: Date.now(), bot: botStatus.online });
});

// Self-ping every 10 min to prevent Render free tier sleep
setInterval(() => {
  const url = PUBLIC_BASE_URL + "/healthz";
  fetch(url).catch(() => {});
}, 10 * 60 * 1000);

// ============================================================
// Start HTTP server
// ============================================================
app.listen(PORT, () => {
  console.log("Solaries server (Phase 6 D2.1) running on port " + PORT);
});

// ============================================================
// DISCORD BOT - embedded, optional
// ============================================================
if (!DISCORD_BOT_TOKEN) {
  console.log("DISCORD_BOT_TOKEN not set - Discord bot disabled");
} else {
  startDiscordBot().catch((err) => {
    console.error("Discord bot failed to start:", err.message);
    botStatus.last_error = err.message;
  });
}

async function startDiscordBot() {
  const { Client, GatewayIntentBits, Events, REST, Routes, SlashCommandBuilder, MessageFlags } = require("discord.js");

  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMembers,
      GatewayIntentBits.GuildMessages,
    ],
  });

  const commands = [
    new SlashCommandBuilder()
      .setName("login")
      .setDescription("Link your Discord to your Solaries account with your API key")
      .addStringOption((opt) =>
        opt.setName("api_key")
          .setDescription("Your Solaries API key (from your dashboard)")
          .setRequired(true)
      )
      .toJSON(),
    new SlashCommandBuilder()
      .setName("whoami")
      .setDescription("Check which Solaries account is linked to your Discord")
      .toJSON(),
    new SlashCommandBuilder()
      .setName("unlink")
      .setDescription("Unlink your Discord from your Solaries account")
      .toJSON(),
    new SlashCommandBuilder()
      .setName("panel")
      .setDescription("Post a Solaries panel for a script in this channel")
      .addStringOption((opt) =>
        opt.setName("script_id")
          .setDescription("The script slug (from your Solaries dashboard)")
          .setRequired(true)
      )
      .addStringOption((opt) =>
        opt.setName("title")
          .setDescription("Optional custom title for the panel")
          .setRequired(false)
      )
      .toJSON(),
  ];

  client.once(Events.ClientReady, async (c) => {
    console.log("Discord bot ready as " + c.user.tag);
    botStatus.online = true;
    botStatus.username = c.user.tag;
    botStatus.guild_count = c.guilds.cache.size;
    botStatus.started_at = new Date().toISOString();

    // Register slash commands globally (may take up to 1 hour to appear)
    // For instant testing in a specific server, set DISCORD_TEST_GUILD_ID env var
    try {
      const rest = new REST({ version: "10" }).setToken(DISCORD_BOT_TOKEN);
      const appId = c.user.id;
      const testGuild = process.env.DISCORD_TEST_GUILD_ID;
      if (testGuild) {
        await rest.put(Routes.applicationGuildCommands(appId, testGuild), { body: commands });
        console.log("Slash commands registered to test guild " + testGuild);
      } else {
        await rest.put(Routes.applicationCommands(appId), { body: commands });
        console.log("Slash commands registered globally");
      }
    } catch (e) {
      console.error("Command registration failed:", e.message);
      botStatus.last_error = "Command registration: " + e.message;
    }
  });

  client.on(Events.GuildCreate, () => {
    botStatus.guild_count = client.guilds.cache.size;
  });
  client.on(Events.GuildDelete, () => {
    botStatus.guild_count = client.guilds.cache.size;
  });

  client.on(Events.InteractionCreate, async (interaction) => {
    try {
      if (interaction.isChatInputCommand()) {
        if (interaction.commandName === "login") {
          await handleLogin(interaction);
        } else if (interaction.commandName === "whoami") {
          await handleWhoami(interaction);
        } else if (interaction.commandName === "unlink") {
          await handleUnlink(interaction);
        } else if (interaction.commandName === "panel") {
          await handlePanel(interaction);
        }
      } else if (interaction.isButton()) {
        // Custom IDs: "sol_getkey_<scriptId>", "sol_getscript_<scriptId>", "sol_resethwid_<scriptId>"
        const parts = interaction.customId.split("_");
        if (parts[0] === "sol") {
          const action = parts[1];
          const scriptId = parts.slice(2).join("_");
          if (action === "getkey") await handleGetKey(interaction, scriptId);
          else if (action === "getscript") await handleGetScript(interaction, scriptId);
          else if (action === "resethwid") await handleResetHwid(interaction, scriptId);
        }
      }
    } catch (e) {
      console.error("Interaction error [" + (interaction.commandName || interaction.customId || "unknown") + "]:", e);
      console.error("Stack:", e.stack);
      try {
        const errText = String(e.message || e || "unknown error").slice(0, 400);
        const msg = "Error: " + errText;
        if (interaction.deferred || interaction.replied) {
          await interaction.editReply({ content: msg });
        } else {
          await interaction.reply({ content: msg, flags: MessageFlags.Ephemeral });
        }
      } catch (replyErr) {
        console.error("Failed to send error reply:", replyErr.message);
      }
    }
  });

  async function handleLogin(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const apiKey = interaction.options.getString("api_key", true).trim();
    const discordId = interaction.user.id;
    const discordUsername = interaction.user.username;

    const { data: account } = await supabase.from("accounts")
      .select("id, name").eq("api_key", apiKey).maybeSingle();

    if (!account) {
      await interaction.editReply({ content: "Invalid API key. Check your Solaries dashboard and try again." });
      return;
    }

    // Check if this Discord is already linked to another account
    const { data: existingLink } = await supabase.from("discord_users")
      .select("id, account_id").eq("discord_id", discordId).maybeSingle();

    if (existingLink) {
      if (existingLink.account_id === account.id) {
        await interaction.editReply({ content: "You are already linked to " + account.name + "." });
        return;
      }
      // Re-link: delete old and insert new
      await supabase.from("discord_users").delete().eq("discord_id", discordId);
    }

    // Also remove any existing link on the target account (one Discord per account)
    await supabase.from("discord_users").delete().eq("account_id", account.id);

    const { error } = await supabase.from("discord_users").insert({
      account_id: account.id,
      discord_id: discordId,
      discord_username: discordUsername,
    });

    if (error) {
      await interaction.editReply({ content: "Could not link account. Try again later." });
      return;
    }

    await interaction.editReply({
      content: "Linked! Your Discord is now connected to Solaries account: " + account.name,
    });
  }

  async function handleWhoami(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;

    const { data: link } = await supabase.from("discord_users")
      .select("account_id, linked_at").eq("discord_id", discordId).maybeSingle();

    if (!link) {
      await interaction.editReply({ content: "Not linked. Use /login <api_key> first." });
      return;
    }

    const { data: account } = await supabase.from("accounts")
      .select("name, plan").eq("id", link.account_id).maybeSingle();

    if (!account) {
      await interaction.editReply({ content: "Linked account no longer exists. Please /login again." });
      return;
    }

    await interaction.editReply({
      content: "Linked to: " + account.name + " (plan: " + account.plan + ")",
    });
  }

  async function handleUnlink(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;
    await supabase.from("discord_users").delete().eq("discord_id", discordId);
    await interaction.editReply({ content: "Unlinked. Use /login to link again." });
  }

  // ============================================================
  // /panel <script_id> - post a panel embed in the channel
  // ============================================================
  async function handlePanel(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const scriptSlug = interaction.options.getString("script_id", true).trim();
    const customTitle = interaction.options.getString("title");
    const discordId = interaction.user.id;

    // Must be logged in
    const { data: link } = await supabase.from("discord_users")
      .select("account_id").eq("discord_id", discordId).maybeSingle();
    if (!link) {
      await interaction.editReply({ content: "You must /login first before posting a panel." });
      return;
    }

    // Load the script and verify ownership
    const { data: script } = await supabase.from("scripts")
      .select("id, name, description, slug, key_mode, projects!inner(name, owner_account_id)")
      .eq("slug", scriptSlug).maybeSingle();

    if (!script) {
      await interaction.editReply({ content: "Script not found. Check the script slug in your dashboard." });
      return;
    }
    if (script.projects.owner_account_id !== link.account_id) {
      await interaction.editReply({ content: "You do not own this script." });
      return;
    }

    // Build embed
    const embed = new EmbedBuilder()
      .setColor(0x8b5cf6)
      .setTitle(customTitle || script.name)
      .setDescription(
        (script.description || "Redeem your key or get your loader script from this panel.") +
        "\n\nHWID resets are limited to once every 15 hours." +
        "\n\nWarning: Sharing your key or loader script may result in the loss of your key or a permanent ban."
      )
      .setFooter({ text: "Powered by Solaries" });

    // Buttons
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("sol_getkey_" + script.id)
        .setLabel("Get Key")
        .setStyle(ButtonStyle.Success),
      new ButtonBuilder()
        .setCustomId("sol_getscript_" + script.id)
        .setLabel("Get Script")
        .setStyle(ButtonStyle.Secondary),
      new ButtonBuilder()
        .setCustomId("sol_resethwid_" + script.id)
        .setLabel("Reset HWID")
        .setStyle(ButtonStyle.Danger)
    );

    // Post the panel message publicly
    const channel = interaction.channel;
    let posted;
    try {
      posted = await channel.send({ embeds: [embed], components: [row] });
    } catch (sendErr) {
      console.error("channel.send failed:", sendErr.code, sendErr.message);
      let hint = sendErr.message || "unknown";
      if (sendErr.code === 50013) hint = "Bot missing permissions in this channel. Grant Send Messages + Embed Links to the Solaries role.";
      else if (sendErr.code === 50001) hint = "Bot cannot access this channel. Add the Solaries role to the channel members.";
      await interaction.editReply({ content: "Could not post panel: " + hint });
      return;
    }

    // Save panel record
    const { error: insertErr } = await supabase.from("discord_panels").insert({
      account_id: link.account_id,
      script_id: script.id,
      guild_id: interaction.guildId,
      channel_id: interaction.channelId,
      message_id: posted.id,
    });
    if (insertErr) {
      console.error("discord_panels insert failed:", insertErr);
      await interaction.editReply({ content: "Panel posted to Discord but could not save record: " + (insertErr.message || "db error") });
      return;
    }

    await interaction.editReply({ content: "Panel posted." });
  }

  // ============================================================
  // Button: Get Key
  // ============================================================
  async function handleGetKey(interaction, scriptId) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;

    // Must be logged in
    const { data: link } = await supabase.from("discord_users")
      .select("account_id").eq("discord_id", discordId).maybeSingle();
    if (!link) {
      await interaction.editReply({ content: "You must /login first to get a key." });
      return;
    }

    // Load script
    const { data: script } = await supabase.from("scripts")
      .select("id, name, project_id, key_mode, projects!inner(owner_account_id)")
      .eq("id", scriptId).maybeSingle();
    if (!script) {
      await interaction.editReply({ content: "Script not found." });
      return;
    }
    if (script.key_mode === "keyless") {
      await interaction.editReply({ content: "This script is keyless - no key needed. Use Get Script instead." });
      return;
    }

    const scriptOwnerId = script.projects.owner_account_id;

    // Check if this Discord user already has a key for this script (one per user per script)
    const { data: existing } = await supabase.from("keys")
      .select("id, key, revoked")
      .eq("discord_id", discordId)
      .eq("project_id", script.project_id)
      .eq("owner_account_id", scriptOwnerId)
      .maybeSingle();

    let keyValue;
    if (existing) {
      if (existing.revoked) {
        await interaction.editReply({ content: "Your key for this script was revoked. Contact the script owner." });
        return;
      }
      keyValue = existing.key;
    } else {
      // Generate new key
      keyValue = makeKey("KF");
      const { error } = await supabase.from("keys").insert({
        owner_account_id: scriptOwnerId,
        project_id: script.project_id,
        key: keyValue,
        label: "Discord: " + interaction.user.username,
        discord_id: discordId,
        hwid_locked: true,
      });
      if (error) {
        await interaction.editReply({ content: "Could not generate key. Try again later." });
        return;
      }
    }

    await interaction.editReply({
      content: "Your key for **" + script.name + "**:\n\n```" + keyValue + "```\n\nKeep this private. Do not share.",
    });
  }

  // ============================================================
  // Button: Get Script (loader URL)
  // ============================================================
  async function handleGetScript(interaction, scriptId) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;

    const { data: script } = await supabase.from("scripts")
      .select("id, name, slug, key_mode, projects!inner(owner_account_id)")
      .eq("id", scriptId).maybeSingle();
    if (!script) {
      await interaction.editReply({ content: "Script not found." });
      return;
    }

    let loader;
    if (script.key_mode === "keyed") {
      // Try to include the user's key if they have one
      const { data: link } = await supabase.from("discord_users")
        .select("account_id").eq("discord_id", discordId).maybeSingle();

      let userKey = null;
      if (link) {
        const { data: existingKey } = await supabase.from("keys")
          .select("key, revoked").eq("discord_id", discordId)
          .eq("owner_account_id", script.projects.owner_account_id).maybeSingle();
        if (existingKey && !existingKey.revoked) userKey = existingKey.key;
      }

      const loaderUrl = PUBLIC_BASE_URL + "/v1/load/" + script.slug;
      if (userKey) {
        loader = 'loadstring(game:HttpGet("' + loaderUrl + '?key=' + userKey + '"))()';
      } else {
        loader = 'local key = "PASTE_YOUR_KEY_HERE"\nloadstring(game:HttpGet("' + loaderUrl + '?key=" .. key))()';
      }
    } else {
      loader = 'loadstring(game:HttpGet("' + PUBLIC_BASE_URL + "/v1/load/" + script.slug + '"))()';
    }

    await interaction.editReply({
      content: "Loader script for **" + script.name + "**:\n\n```lua\n" + loader + "\n```",
    });
  }

  // ============================================================
  // Button: Reset HWID (15h cooldown)
  // ============================================================
  async function handleResetHwid(interaction, scriptId) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;
    const COOLDOWN_MS = 15 * 60 * 60 * 1000; // 15 hours

    const { data: script } = await supabase.from("scripts")
      .select("id, project_id, projects!inner(owner_account_id)")
      .eq("id", scriptId).maybeSingle();
    if (!script) {
      await interaction.editReply({ content: "Script not found." });
      return;
    }

    const { data: keyRow } = await supabase.from("keys")
      .select("id, hwid, last_hwid_reset, revoked")
      .eq("discord_id", discordId)
      .eq("project_id", script.project_id)
      .eq("owner_account_id", script.projects.owner_account_id)
      .maybeSingle();

    if (!keyRow) {
      await interaction.editReply({ content: "You do not have a key for this script yet. Click Get Key first." });
      return;
    }
    if (keyRow.revoked) {
      await interaction.editReply({ content: "Your key is revoked. Contact the script owner." });
      return;
    }
    if (!keyRow.hwid) {
      await interaction.editReply({ content: "No HWID is bound to your key yet - nothing to reset." });
      return;
    }

    if (keyRow.last_hwid_reset) {
      const elapsed = Date.now() - new Date(keyRow.last_hwid_reset).getTime();
      if (elapsed < COOLDOWN_MS) {
        const remaining = COOLDOWN_MS - elapsed;
        const hours = Math.floor(remaining / (60 * 60 * 1000));
        const mins = Math.floor((remaining % (60 * 60 * 1000)) / (60 * 1000));
        await interaction.editReply({
          content: "Cooldown active. Try again in " + hours + "h " + mins + "m.",
        });
        return;
      }
    }

    const { error } = await supabase.from("keys")
      .update({ hwid: null, last_hwid_reset: new Date().toISOString() })
      .eq("id", keyRow.id);
    if (error) {
      await interaction.editReply({ content: "Could not reset HWID. Try again later." });
      return;
    }

    await interaction.editReply({
      content: "HWID reset. Next reset will be available in 15 hours.",
    });
  }

  await client.login(DISCORD_BOT_TOKEN);
}
