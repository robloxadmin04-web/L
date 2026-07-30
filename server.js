// server.js - Solaries Phase 6 (Discord Bot D9 - custom script slug on create)
// Full command list: /login /logout /whoami /panel /managerrole /stats /settings
// /key create|stock|delete|extend|revoke|info|list
// /user info|blacklist|unblacklist|ban|unban  /hwid reset  /whitelist
// /project create|delete|list|select  /buyerrole set|clear|list  /setscript
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

  // Custom slug handling with validation + uniqueness check
  let finalSlug;
  const customSlug = String(body.slug || "").trim().toLowerCase();
  if (customSlug) {
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(customSlug) || customSlug.length < 3 || customSlug.length > 40) {
      return res.status(400).json({ ok: false, error: "Slug must be 3-40 chars, lowercase a-z, 0-9, and dashes only. Cannot start/end with dash." });
    }
    const { data: existing } = await supabase.from("scripts")
      .select("id").eq("project_id", req.params.pid).eq("slug", customSlug).maybeSingle();
    if (existing) return res.status(400).json({ ok: false, error: "Slug already used in this project. Pick a different one." });
    finalSlug = customSlug;
  } else {
    finalSlug = makeSlug(name);
  }

  const source = String(body.source || "");
  const insert = {
    project_id: req.params.pid, name, slug: finalSlug,
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
// STEP 2: Add these routes to server.js
// ------------------------------------------------------------
// Paste this block anywhere AFTER `requireOwner` is defined and
// AFTER `app` + `supabase` are set up. The existing Discord routes
// section (// DISCORD ...) is a good neighbour to drop it near.
// ============================================================

// --- PUBLIC: index.html reads the current Discord invite (no auth) ---
app.get("/api/discord/invite", async (req, res) => {
  const { data, error } = await supabase
    .from("settings")
    .select("value")
    .eq("key", "discord_invite")
    .maybeSingle();
  if (error) return res.status(500).json({ ok: false, error: "Server error" });
  res.json({ ok: true, invite: (data && data.value) || "" });
});

// --- OWNER: update the Discord invite from owner.html ---
app.post("/api/settings/discord", requireAuth, requireOwner, async (req, res) => {
  const invite = (req.body?.invite || "").trim();

  // Basic validation: must be a discord.gg / discord invite link
  const ok = /^https:\/\/(discord\.gg|discord\.com\/invite)\/[A-Za-z0-9-]+$/.test(invite);
  if (!ok) {
    return res.status(400).json({
      ok: false,
      error: "Enter a valid invite, e.g. https://discord.gg/xxxxxxx",
    });
  }

  const { error } = await supabase
    .from("settings")
    .upsert(
      { key: "discord_invite", value: invite, updated_at: new Date().toISOString() },
      { onConflict: "key" }
    );
  if (error) return res.status(500).json({ ok: false, error: "Could not save" });
  res.json({ ok: true, invite });
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
  console.log("Solaries server (Phase 6 D9) running on port " + PORT);
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
  const { Client, GatewayIntentBits, Events, REST, Routes, SlashCommandBuilder, MessageFlags, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle } = require("discord.js");

  // Helper: try to send DM, return true if delivered
  async function trySendDM(discordId, payload) {
    try {
      const user = await client.users.fetch(discordId);
      await user.send(payload);
      return true;
    } catch (e) {
      return false;
    }
  }

  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMembers,
      GatewayIntentBits.GuildMessages,
    ],
  });

  // Discord ManageGuild permission (bit flag 32)
  const MANAGE_GUILD = "32";

  const commands = [
    // ---------- SETUP / SESSION ----------
    new SlashCommandBuilder()
      .setName("login")
      .setDescription("Link this server to your Solaries account (API key)")
      .addStringOption((o) => o.setName("api_key").setDescription("Your Solaries API key").setRequired(true))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("logout")
      .setDescription("Unlink this Discord from your Solaries account")
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("whoami")
      .setDescription("Show which Solaries account is linked to your Discord")
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("panel")
      .setDescription("Post a Solaries panel for a script in this channel")
      .addStringOption((o) => o.setName("script_id").setDescription("Script slug").setRequired(true))
      .addStringOption((o) => o.setName("title").setDescription("Optional custom title").setRequired(false))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("managerrole")
      .setDescription("Set/clear which Discord role can run management commands")
      .addSubcommand((s) => s.setName("set").setDescription("Add a manager role")
        .addRoleOption((o) => o.setName("role").setDescription("Discord role").setRequired(true)))
      .addSubcommand((s) => s.setName("clear").setDescription("Remove a manager role")
        .addRoleOption((o) => o.setName("role").setDescription("Discord role").setRequired(true)))
      .addSubcommand((s) => s.setName("list").setDescription("List manager roles"))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),

    // ---------- STATS / SETTINGS ----------
    new SlashCommandBuilder()
      .setName("stats")
      .setDescription("View project statistics (keys, users, executions)")
      .addStringOption((o) => o.setName("project").setDescription("Project slug (default: active)").setRequired(false))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("settings")
      .setDescription("View or configure bot settings")
      .addSubcommand((s) => s.setName("view").setDescription("View current settings"))
      .addSubcommand((s) => s.setName("keyprefix").setDescription("Set default key prefix")
        .addStringOption((o) => o.setName("value").setDescription("Prefix (max 6 A-Z0-9)").setRequired(true)))
      .addSubcommand((s) => s.setName("expiry").setDescription("Set default expiry days")
        .addIntegerOption((o) => o.setName("days").setDescription("Default days (0 = no expiry)").setRequired(true)))
      .addSubcommand((s) => s.setName("cooldown").setDescription("Set HWID reset cooldown hours")
        .addIntegerOption((o) => o.setName("hours").setDescription("Cooldown hours").setRequired(true)))
      .addSubcommand((s) => s.setName("logchannel").setDescription("Set log channel")
        .addChannelOption((o) => o.setName("channel").setDescription("Log channel").setRequired(true)))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),

    // ---------- KEY MANAGEMENT ----------
    new SlashCommandBuilder()
      .setName("key")
      .setDescription("Manage keys")
      .addSubcommand((s) => s.setName("create").setDescription("Generate a key")
        .addStringOption((o) => o.setName("project").setDescription("Project slug").setRequired(false))
        .addStringOption((o) => o.setName("label").setDescription("Label").setRequired(false))
        .addIntegerOption((o) => o.setName("expires_days").setDescription("Expires in N days").setRequired(false))
        .addBooleanOption((o) => o.setName("hwid_lock").setDescription("HWID locked (default true)").setRequired(false)))
      .addSubcommand((s) => s.setName("stock").setDescription("Bulk generate keys")
        .addIntegerOption((o) => o.setName("count").setDescription("How many (max 50)").setRequired(true))
        .addStringOption((o) => o.setName("project").setDescription("Project slug").setRequired(false))
        .addIntegerOption((o) => o.setName("expires_days").setDescription("Expires in N days").setRequired(false)))
      .addSubcommand((s) => s.setName("delete").setDescription("Delete a key")
        .addStringOption((o) => o.setName("key").setDescription("Key value").setRequired(true)))
      .addSubcommand((s) => s.setName("extend").setDescription("Extend key expiry")
        .addStringOption((o) => o.setName("key").setDescription("Key value").setRequired(true))
        .addIntegerOption((o) => o.setName("days").setDescription("Days to add").setRequired(true)))
      .addSubcommand((s) => s.setName("revoke").setDescription("Revoke a key")
        .addStringOption((o) => o.setName("key").setDescription("Key value").setRequired(true)))
      .addSubcommand((s) => s.setName("info").setDescription("View key info")
        .addStringOption((o) => o.setName("key").setDescription("Key value").setRequired(true)))
      .addSubcommand((s) => s.setName("list").setDescription("List keys in a project")
        .addStringOption((o) => o.setName("project").setDescription("Project slug").setRequired(false)))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),

    // ---------- USER MANAGEMENT ----------
    new SlashCommandBuilder()
      .setName("user")
      .setDescription("Manage users")
      .addSubcommand((s) => s.setName("info").setDescription("View a user's info")
        .addUserOption((o) => o.setName("target").setDescription("Discord user").setRequired(true)))
      .addSubcommand((s) => s.setName("blacklist").setDescription("Blacklist a user (blocks key generation)")
        .addUserOption((o) => o.setName("target").setDescription("Discord user").setRequired(true))
        .addStringOption((o) => o.setName("reason").setDescription("Reason").setRequired(false)))
      .addSubcommand((s) => s.setName("unblacklist").setDescription("Remove blacklist")
        .addUserOption((o) => o.setName("target").setDescription("Discord user").setRequired(true)))
      .addSubcommand((s) => s.setName("ban").setDescription("Full ban (revokes all keys)")
        .addUserOption((o) => o.setName("target").setDescription("Discord user").setRequired(true))
        .addStringOption((o) => o.setName("reason").setDescription("Reason").setRequired(false)))
      .addSubcommand((s) => s.setName("unban").setDescription("Remove ban")
        .addUserOption((o) => o.setName("target").setDescription("Discord user").setRequired(true)))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("hwid")
      .setDescription("HWID management")
      .addSubcommand((s) => s.setName("reset").setDescription("Force reset a user's HWID")
        .addUserOption((o) => o.setName("target").setDescription("Discord user").setRequired(true))
        .addStringOption((o) => o.setName("project").setDescription("Project slug").setRequired(false)))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("whitelist")
      .setDescription("Whitelist a user (grants access + buyer role)")
      .addUserOption((o) => o.setName("target").setDescription("Discord user").setRequired(true))
      .addStringOption((o) => o.setName("project").setDescription("Project slug").setRequired(false))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),

    // ---------- PROJECT MANAGEMENT ----------
    new SlashCommandBuilder()
      .setName("project")
      .setDescription("Manage projects")
      .addSubcommand((s) => s.setName("create").setDescription("Create a project")
        .addStringOption((o) => o.setName("name").setDescription("Project name").setRequired(true))
        .addStringOption((o) => o.setName("note").setDescription("Optional note").setRequired(false)))
      .addSubcommand((s) => s.setName("delete").setDescription("Delete a project")
        .addStringOption((o) => o.setName("slug").setDescription("Project slug").setRequired(true)))
      .addSubcommand((s) => s.setName("list").setDescription("View all projects"))
      .addSubcommand((s) => s.setName("select").setDescription("Set active project for commands")
        .addStringOption((o) => o.setName("slug").setDescription("Project slug").setRequired(true)))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("buyerrole")
      .setDescription("Auto-assign a Discord role after a user redeems a key")
      .addSubcommand((s) => s.setName("set").setDescription("Set buyer role for a project")
        .addRoleOption((o) => o.setName("role").setDescription("Discord role").setRequired(true))
        .addStringOption((o) => o.setName("project").setDescription("Project slug").setRequired(false)))
      .addSubcommand((s) => s.setName("clear").setDescription("Clear buyer role for a project")
        .addStringOption((o) => o.setName("project").setDescription("Project slug").setRequired(false)))
      .addSubcommand((s) => s.setName("list").setDescription("List all buyer roles"))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),
    new SlashCommandBuilder()
      .setName("setscript")
      .setDescription("Set the active script for the active project")
      .addStringOption((o) => o.setName("script_id").setDescription("Script slug").setRequired(true))
      .setDefaultMemberPermissions(MANAGE_GUILD)
      .toJSON(),

    // ---------- USER COMMANDS (no permission gate) ----------
    new SlashCommandBuilder()
      .setName("redeem")
      .setDescription("Redeem a key and bind it to your Discord")
      .addStringOption((o) => o.setName("key").setDescription("Your key value").setRequired(true))
      .toJSON(),
    new SlashCommandBuilder()
      .setName("loader")
      .setDescription("Get the loader script (with your key if you have one)")
      .addStringOption((o) => o.setName("script_id").setDescription("Script slug").setRequired(true))
      .toJSON(),
    new SlashCommandBuilder()
      .setName("script")
      .setDescription("Get the raw loader URL for a script")
      .addStringOption((o) => o.setName("script_id").setDescription("Script slug").setRequired(true))
      .toJSON(),
    new SlashCommandBuilder()
      .setName("resethwid")
      .setDescription("Reset your own HWID (15h cooldown)")
      .addStringOption((o) => o.setName("script_id").setDescription("Script slug").setRequired(true))
      .toJSON(),
    new SlashCommandBuilder()
      .setName("claimrole")
      .setDescription("Claim buyer role if you have a valid key")
      .addStringOption((o) => o.setName("script_id").setDescription("Script slug").setRequired(true))
      .toJSON(),
    new SlashCommandBuilder()
      .setName("mykey")
      .setDescription("View your redeemed keys")
      .toJSON(),
    new SlashCommandBuilder()
      .setName("myproject")
      .setDescription("View the projects you have keys in")
      .toJSON(),
    new SlashCommandBuilder()
      .setName("subscription")
      .setDescription("Check your key's expiry status")
      .addStringOption((o) => o.setName("script_id").setDescription("Script slug").setRequired(false))
      .toJSON(),
    new SlashCommandBuilder()
      .setName("profile")
      .setDescription("View your Discord link and stats")
      .toJSON(),
    new SlashCommandBuilder()
      .setName("help")
      .setDescription("Show commands available to you")
      .toJSON(),
    new SlashCommandBuilder()
      .setName("status")
      .setDescription("Check Solaries service status")
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
        const cmd = interaction.commandName;
        const sub = interaction.options.getSubcommand(false);
        // Setup / session
        if (cmd === "login") await handleLogin(interaction);
        else if (cmd === "logout") await handleLogout(interaction);
        else if (cmd === "whoami") await handleWhoami(interaction);
        else if (cmd === "panel") await handlePanel(interaction);
        else if (cmd === "managerrole") await handleManagerRole(interaction, sub);
        // Stats / settings
        else if (cmd === "stats") await handleStats(interaction);
        else if (cmd === "settings") await handleSettings(interaction, sub);
        // Key management
        else if (cmd === "key") await handleKeyGroup(interaction, sub);
        // User management
        else if (cmd === "user") await handleUserGroup(interaction, sub);
        else if (cmd === "hwid") await handleHwidGroup(interaction, sub);
        else if (cmd === "whitelist") await handleWhitelist(interaction);
        // Project management
        else if (cmd === "project") await handleProjectGroup(interaction, sub);
        else if (cmd === "buyerrole") await handleBuyerRoleGroup(interaction, sub);
        else if (cmd === "setscript") await handleSetScript(interaction);
        // User commands (no admin gate)
        else if (cmd === "redeem") await handleRedeem(interaction);
        else if (cmd === "loader") await handleLoader(interaction);
        else if (cmd === "script") await handleScriptCmd(interaction);
        else if (cmd === "resethwid") await handleResetHwidCmd(interaction);
        else if (cmd === "claimrole") await handleClaimRole(interaction);
        else if (cmd === "mykey") await handleMyKey(interaction);
        else if (cmd === "myproject") await handleMyProject(interaction);
        else if (cmd === "subscription") await handleSubscription(interaction);
        else if (cmd === "profile") await handleProfile(interaction);
        else if (cmd === "help") await handleHelp(interaction);
        else if (cmd === "status") await handleStatus(interaction);
      } else if (interaction.isButton()) {
        // Custom IDs: "sol_<action>_<scriptId>"
        const parts = interaction.customId.split("_");
        if (parts[0] === "sol") {
          const action = parts[1];
          const scriptId = parts.slice(2).join("_");
          if (action === "redeem") await handleRedeemButton(interaction, scriptId);
          else if (action === "getrole") await handleGetRoleButton(interaction, scriptId);
          else if (action === "getscript") await handleGetScript(interaction, scriptId);
          else if (action === "resethwid") await handleResetHwid(interaction, scriptId);
          else if (action === "session") await handleSessionStatus(interaction, scriptId);
          else if (action === "getkey") await handleGetKey(interaction, scriptId);
        }
      } else if (interaction.isModalSubmit()) {
        const parts = interaction.customId.split("_");
        if (parts[0] === "sol" && parts[1] === "redeemmodal") {
          const scriptId = parts.slice(2).join("_");
          await handleRedeemSubmit(interaction, scriptId);
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
        (script.description || "Redeem your key, claim your buyer role, or get your script loader from this panel.") +
        "\n\nHWID resets are limited to once every 15 hours - First reset becomes available 15 hours after redeeming your key." +
        "\n\nWarning: Sharing your key or loader script may result in the loss of your key or a permanent ban."
      )
      .setFooter({ text: "Powered by Solaries" });

    // Buttons - row 1 (Redeem Key, Get Role, Get Script)
    const row1 = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("sol_redeem_" + script.id)
        .setLabel("Redeem Key")
        .setStyle(ButtonStyle.Success),
      new ButtonBuilder()
        .setCustomId("sol_getrole_" + script.id)
        .setLabel("Get Role")
        .setStyle(ButtonStyle.Primary),
      new ButtonBuilder()
        .setCustomId("sol_getscript_" + script.id)
        .setLabel("Get Script")
        .setStyle(ButtonStyle.Secondary)
    );
    // Buttons - row 2 (Reset HWID, Session Status)
    const row2 = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId("sol_resethwid_" + script.id)
        .setLabel("Reset HWID")
        .setStyle(ButtonStyle.Danger),
      new ButtonBuilder()
        .setCustomId("sol_session_" + script.id)
        .setLabel("Session Status")
        .setStyle(ButtonStyle.Secondary)
    );

    // Post the panel message publicly
    const channel = interaction.channel;
    let posted;
    try {
      posted = await channel.send({ embeds: [embed], components: [row1, row2] });
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
      .select("id, name, slug, key_mode, enabled, project_id, projects!inner(owner_account_id, status)")
      .eq("id", scriptId).maybeSingle();
    if (!script) {
      await interaction.editReply({ content: "Script not found." });
      return;
    }
    if (!script.enabled) {
      const embed = new EmbedBuilder().setColor(0xef4444).setTitle("Script Disabled")
        .setDescription("This script is currently disabled. Contact the script owner.");
      return interaction.editReply({ embeds: [embed] });
    }
    if (script.projects.status === "paused") {
      const embed = new EmbedBuilder().setColor(0xef4444).setTitle("Project Paused")
        .setDescription("The project is currently paused. Contact the script owner.");
      return interaction.editReply({ embeds: [embed] });
    }

    let loader;
    let userKey = null;
    if (script.key_mode === "keyed") {
      const { data: existingKey } = await supabase.from("keys")
        .select("key, revoked, expires_at").eq("discord_id", discordId)
        .eq("project_id", script.project_id)
        .eq("owner_account_id", script.projects.owner_account_id).maybeSingle();

      if (!existingKey) {
        const embed = new EmbedBuilder().setColor(0xef4444).setTitle("No Active License")
          .setDescription("You need to redeem a key first. Click **Redeem Key** on the panel to get started.");
        return interaction.editReply({ embeds: [embed] });
      }
      if (existingKey.revoked) {
        const embed = new EmbedBuilder().setColor(0xef4444).setTitle("Key Revoked")
          .setDescription("Your key has been revoked. Contact the script owner.");
        return interaction.editReply({ embeds: [embed] });
      }
      if (existingKey.expires_at && new Date(existingKey.expires_at).getTime() < Date.now()) {
        const embed = new EmbedBuilder().setColor(0xef4444).setTitle("Key Expired")
          .setDescription("Your key has expired. Renew or contact the script owner.");
        return interaction.editReply({ embeds: [embed] });
      }
      userKey = existingKey.key;

      const loaderUrl = PUBLIC_BASE_URL + "/v1/load/" + script.slug;
      loader = '_G.script_key = "' + userKey + '"\nloadstring(game:HttpGet("' + loaderUrl + '?key=".._G.script_key))()';
    } else {
      loader = 'loadstring(game:HttpGet("' + PUBLIC_BASE_URL + "/v1/load/" + script.slug + '"))()';
    }

    const dmContent = "Loader script for **" + script.name + "**:\n\n```lua\n" + loader + "\n```\n\nKeep this private. Do not share.";

    const dmSent = await trySendDM(discordId, { content: dmContent });
    if (dmSent) {
      await interaction.editReply({ content: "Sent loader script to your DMs. Check your Discord messages." });
    } else {
      await interaction.editReply({
        content: "Could not DM you (DMs may be closed). Here it is:\n\n" + dmContent + "\n\nEnable DMs from server members to receive scripts privately.",
      });
    }
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


  // ============================================================
  // HELPERS
  // ============================================================
  async function requireLogin(interaction) {
    const { data: link } = await supabase.from("discord_users")
      .select("account_id").eq("discord_id", interaction.user.id).maybeSingle();
    if (!link) {
      await interaction.editReply({ content: "You must /login first with your Solaries API key." });
      return null;
    }
    return link.account_id;
  }

  async function isManagerAllowed(interaction, accountId) {
    // Owner/creator (linked account) always allowed
    // Additional: user has a role in discord_manager_roles
    if (!interaction.guildId) return true;
    if (interaction.memberPermissions && interaction.memberPermissions.has("ManageGuild")) return true;
    const { data: roles } = await supabase.from("discord_manager_roles")
      .select("role_id").eq("account_id", accountId).eq("guild_id", interaction.guildId);
    if (!roles || roles.length === 0) return interaction.memberPermissions?.has("ManageGuild") ?? false;
    const userRoles = interaction.member?.roles?.cache;
    if (!userRoles) return false;
    return roles.some((r) => userRoles.has(r.role_id));
  }

  async function getActiveProject(discordId, accountId, slugOverride) {
    if (slugOverride) {
      const { data } = await supabase.from("projects")
        .select("*").eq("slug", slugOverride).eq("owner_account_id", accountId).maybeSingle();
      return data || null;
    }
    const { data: ctx } = await supabase.from("discord_user_context")
      .select("active_project_id").eq("discord_id", discordId).maybeSingle();
    if (!ctx || !ctx.active_project_id) return null;
    const { data } = await supabase.from("projects")
      .select("*").eq("id", ctx.active_project_id).eq("owner_account_id", accountId).maybeSingle();
    return data || null;
  }

  async function isBlacklisted(accountId, discordId) {
    const { data } = await supabase.from("blacklist")
      .select("id, banned, reason").eq("account_id", accountId).eq("discord_id", discordId).maybeSingle();
    return data || null;
  }

  async function getSettings(accountId) {
    const { data } = await supabase.from("discord_settings")
      .select("*").eq("account_id", accountId).maybeSingle();
    return data || { key_prefix: "KF", default_expiry_days: 30, hwid_cooldown_hours: 15 };
  }

  // ============================================================
  // /logout
  // ============================================================
  async function handleLogout(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;
    await supabase.from("discord_users").delete().eq("discord_id", discordId);
    await supabase.from("discord_user_context").delete().eq("discord_id", discordId);
    await interaction.editReply({ content: "Logged out. Use /login to link again." });
  }

  // ============================================================
  // /managerrole set|clear|list
  // ============================================================
  async function handleManagerRole(interaction, sub) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!interaction.guildId) return interaction.editReply({ content: "This command must be run in a server." });

    if (sub === "set") {
      const role = interaction.options.getRole("role", true);
      const { error } = await supabase.from("discord_manager_roles").insert({
        account_id: accountId, guild_id: interaction.guildId, role_id: role.id,
      });
      if (error && !error.message.includes("duplicate")) {
        return interaction.editReply({ content: "Error: " + error.message });
      }
      return interaction.editReply({ content: "Manager role set: " + role.name });
    }
    if (sub === "clear") {
      const role = interaction.options.getRole("role", true);
      await supabase.from("discord_manager_roles").delete()
        .eq("account_id", accountId).eq("guild_id", interaction.guildId).eq("role_id", role.id);
      return interaction.editReply({ content: "Manager role removed: " + role.name });
    }
    if (sub === "list") {
      const { data } = await supabase.from("discord_manager_roles")
        .select("role_id").eq("account_id", accountId).eq("guild_id", interaction.guildId);
      if (!data || data.length === 0) return interaction.editReply({ content: "No manager roles set. Members with Discord ManageGuild permission can still use admin commands." });
      const list = data.map((r) => "<@&" + r.role_id + ">").join(", ");
      return interaction.editReply({ content: "Manager roles: " + list });
    }
  }

  // ============================================================
  // /stats
  // ============================================================
  async function handleStats(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });

    const slug = interaction.options.getString("project");
    const project = await getActiveProject(interaction.user.id, accountId, slug);

    if (project) {
      const [scripts, keys, revoked, loads24h] = await Promise.all([
        supabase.from("scripts").select("id", { count: "exact", head: true }).eq("project_id", project.id),
        supabase.from("keys").select("id", { count: "exact", head: true }).eq("project_id", project.id),
        supabase.from("keys").select("id", { count: "exact", head: true }).eq("project_id", project.id).eq("revoked", true),
        supabase.from("access_log").select("id", { count: "exact", head: true }).eq("project_id", project.id).eq("event", "load").gte("created_at", new Date(Date.now() - 86400000).toISOString()),
      ]);
      const embed = new EmbedBuilder()
        .setColor(0x8b5cf6).setTitle("Stats - " + project.name)
        .addFields(
          { name: "Scripts", value: String(scripts.count || 0), inline: true },
          { name: "Keys total", value: String(keys.count || 0), inline: true },
          { name: "Active", value: String((keys.count || 0) - (revoked.count || 0)), inline: true },
          { name: "Revoked", value: String(revoked.count || 0), inline: true },
          { name: "Loads 24h", value: String(loads24h.count || 0), inline: true },
          { name: "Status", value: project.status, inline: true },
        );
      return interaction.editReply({ embeds: [embed] });
    }

    // Account-wide stats
    const [projs, scripts, keys, loads24h] = await Promise.all([
      supabase.from("projects").select("id", { count: "exact", head: true }).eq("owner_account_id", accountId),
      supabase.from("scripts").select("id, projects!inner(owner_account_id)", { count: "exact", head: true }).eq("projects.owner_account_id", accountId),
      supabase.from("keys").select("id", { count: "exact", head: true }).eq("owner_account_id", accountId),
      supabase.from("access_log").select("id", { count: "exact", head: true }).eq("owner_account_id", accountId).eq("event", "load").gte("created_at", new Date(Date.now() - 86400000).toISOString()),
    ]);
    const embed = new EmbedBuilder()
      .setColor(0x8b5cf6).setTitle("Account Stats")
      .addFields(
        { name: "Projects", value: String(projs.count || 0), inline: true },
        { name: "Scripts", value: String(scripts.count || 0), inline: true },
        { name: "Keys", value: String(keys.count || 0), inline: true },
        { name: "Loads 24h", value: String(loads24h.count || 0), inline: true },
      );
    interaction.editReply({ embeds: [embed] });
  }

  // ============================================================
  // /settings view|keyprefix|expiry|cooldown|logchannel
  // ============================================================
  async function handleSettings(interaction, sub) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });

    if (sub === "view") {
      const s = await getSettings(accountId);
      const embed = new EmbedBuilder().setColor(0x8b5cf6).setTitle("Bot Settings")
        .addFields(
          { name: "Key Prefix", value: s.key_prefix || "KF", inline: true },
          { name: "Default Expiry", value: (s.default_expiry_days || 30) + " days", inline: true },
          { name: "HWID Cooldown", value: (s.hwid_cooldown_hours || 15) + " hours", inline: true },
          { name: "Log Channel", value: s.log_channel_id ? "<#" + s.log_channel_id + ">" : "Not set", inline: false },
        );
      return interaction.editReply({ embeds: [embed] });
    }
    const patch = { account_id: accountId, updated_at: new Date().toISOString() };
    if (sub === "keyprefix") patch.key_prefix = interaction.options.getString("value", true).toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 6) || "KF";
    if (sub === "expiry") patch.default_expiry_days = Math.max(0, interaction.options.getInteger("days", true));
    if (sub === "cooldown") patch.hwid_cooldown_hours = Math.max(0, interaction.options.getInteger("hours", true));
    if (sub === "logchannel") patch.log_channel_id = interaction.options.getChannel("channel", true).id;

    const { error } = await supabase.from("discord_settings").upsert(patch, { onConflict: "account_id" });
    if (error) return interaction.editReply({ content: "Error: " + error.message });
    interaction.editReply({ content: "Setting updated." });
  }

  // ============================================================
  // /key group
  // ============================================================
  async function handleKeyGroup(interaction, sub) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });

    if (sub === "create") return keyCreate(interaction, accountId);
    if (sub === "stock") return keyStock(interaction, accountId);
    if (sub === "delete") return keyDelete(interaction, accountId);
    if (sub === "extend") return keyExtend(interaction, accountId);
    if (sub === "revoke") return keyRevoke(interaction, accountId);
    if (sub === "info") return keyInfo(interaction, accountId);
    if (sub === "list") return keyList(interaction, accountId);
  }

  async function keyCreate(interaction, accountId) {
    const slug = interaction.options.getString("project");
    const project = await getActiveProject(interaction.user.id, accountId, slug);
    if (!project) return interaction.editReply({ content: "No project. Use /project select or pass project: slug." });
    const settings = await getSettings(accountId);
    const label = interaction.options.getString("label") || null;
    const days = interaction.options.getInteger("expires_days");
    const hwidLock = interaction.options.getBoolean("hwid_lock");
    const key = makeKey(settings.key_prefix || "KF");
    const insert = {
      owner_account_id: accountId, project_id: project.id, key, label,
      hwid_locked: hwidLock !== null && hwidLock !== undefined ? hwidLock : true,
    };
    const expiryDays = days !== null && days !== undefined ? days : (settings.default_expiry_days || 0);
    if (expiryDays > 0) insert.expires_at = new Date(Date.now() + expiryDays * 86400000).toISOString();
    const { error } = await supabase.from("keys").insert(insert);
    if (error) return interaction.editReply({ content: "Error: " + error.message });
    interaction.editReply({ content: "Key created for **" + project.name + "**:\n\n```" + key + "```" + (expiryDays > 0 ? "\nExpires in " + expiryDays + " days." : "\nNo expiry.") });
  }

  async function keyStock(interaction, accountId) {
    const count = Math.min(Math.max(1, interaction.options.getInteger("count", true)), 50);
    const slug = interaction.options.getString("project");
    const project = await getActiveProject(interaction.user.id, accountId, slug);
    if (!project) return interaction.editReply({ content: "No project selected." });
    const settings = await getSettings(accountId);
    const days = interaction.options.getInteger("expires_days");
    const expiryDays = days !== null && days !== undefined ? days : (settings.default_expiry_days || 0);
    const rows = [];
    for (let i = 0; i < count; i++) {
      const k = makeKey(settings.key_prefix || "KF");
      const row = { owner_account_id: accountId, project_id: project.id, key: k, hwid_locked: true, label: "Bulk stock" };
      if (expiryDays > 0) row.expires_at = new Date(Date.now() + expiryDays * 86400000).toISOString();
      rows.push(row);
    }
    const { data, error } = await supabase.from("keys").insert(rows).select("key");
    if (error) return interaction.editReply({ content: "Error: " + error.message });
    const list = (data || []).map((r) => r.key).join("\n");
    interaction.editReply({ content: "Generated " + count + " keys for **" + project.name + "**:\n\n```" + list + "```" });
  }

  async function keyDelete(interaction, accountId) {
    const key = interaction.options.getString("key", true).trim();
    const { data } = await supabase.from("keys").select("id").eq("key", key).eq("owner_account_id", accountId).maybeSingle();
    if (!data) return interaction.editReply({ content: "Key not found or not yours." });
    await supabase.from("keys").delete().eq("id", data.id);
    interaction.editReply({ content: "Key deleted." });
  }

  async function keyExtend(interaction, accountId) {
    const key = interaction.options.getString("key", true).trim();
    const days = interaction.options.getInteger("days", true);
    const { data } = await supabase.from("keys").select("id, expires_at").eq("key", key).eq("owner_account_id", accountId).maybeSingle();
    if (!data) return interaction.editReply({ content: "Key not found or not yours." });
    const base = data.expires_at ? new Date(data.expires_at).getTime() : Date.now();
    const newExpiry = new Date(base + days * 86400000).toISOString();
    await supabase.from("keys").update({ expires_at: newExpiry }).eq("id", data.id);
    interaction.editReply({ content: "Extended by " + days + " days. New expiry: " + newExpiry });
  }

  async function keyRevoke(interaction, accountId) {
    const key = interaction.options.getString("key", true).trim();
    const { data } = await supabase.from("keys").select("id").eq("key", key).eq("owner_account_id", accountId).maybeSingle();
    if (!data) return interaction.editReply({ content: "Key not found or not yours." });
    await supabase.from("keys").update({ revoked: true }).eq("id", data.id);
    interaction.editReply({ content: "Key revoked." });
  }

  async function keyInfo(interaction, accountId) {
    const key = interaction.options.getString("key", true).trim();
    const { data } = await supabase.from("keys").select("*, projects(name, slug)").eq("key", key).eq("owner_account_id", accountId).maybeSingle();
    if (!data) return interaction.editReply({ content: "Key not found or not yours." });
    const embed = new EmbedBuilder().setColor(0x8b5cf6).setTitle("Key Info")
      .addFields(
        { name: "Key", value: "`" + data.key + "`", inline: false },
        { name: "Project", value: data.projects?.name || "-", inline: true },
        { name: "Label", value: data.label || "-", inline: true },
        { name: "Status", value: data.revoked ? "Revoked" : "Active", inline: true },
        { name: "HWID", value: data.hwid || "Not bound", inline: true },
        { name: "HWID Lock", value: data.hwid_locked ? "Yes" : "No", inline: true },
        { name: "Discord ID", value: data.discord_id || "-", inline: true },
        { name: "Expires", value: data.expires_at || "Never", inline: false },
        { name: "Created", value: data.created_at, inline: true },
        { name: "Last used", value: data.last_used_at || "Never", inline: true },
      );
    interaction.editReply({ embeds: [embed] });
  }

  async function keyList(interaction, accountId) {
    const slug = interaction.options.getString("project");
    const project = await getActiveProject(interaction.user.id, accountId, slug);
    if (!project) return interaction.editReply({ content: "No project selected." });
    const { data } = await supabase.from("keys").select("key, revoked, label, expires_at")
      .eq("project_id", project.id).order("created_at", { ascending: false }).limit(25);
    if (!data || data.length === 0) return interaction.editReply({ content: "No keys in " + project.name });
    const lines = data.map((k) => (k.revoked ? "~~" : "") + k.key + (k.revoked ? "~~" : "") + (k.label ? " (" + k.label + ")" : "")).join("\n");
    interaction.editReply({ content: "**Keys in " + project.name + "** (latest 25):\n" + lines });
  }

  // ============================================================
  // /user group
  // ============================================================
  async function handleUserGroup(interaction, sub) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });
    const target = interaction.options.getUser("target", true);

    if (sub === "info") {
      const { data: link } = await supabase.from("discord_users").select("account_id, linked_at").eq("discord_id", target.id).maybeSingle();
      const { data: keys } = await supabase.from("keys").select("key, revoked, project_id, projects(name)").eq("discord_id", target.id).eq("owner_account_id", accountId);
      const bl = await isBlacklisted(accountId, target.id);
      const embed = new EmbedBuilder().setColor(0x8b5cf6).setTitle("User: " + target.username)
        .addFields(
          { name: "Discord", value: "<@" + target.id + ">", inline: true },
          { name: "Linked", value: link ? "Yes (" + link.linked_at + ")" : "No", inline: true },
          { name: "Blacklisted", value: bl ? "Yes" + (bl.banned ? " (BANNED)" : "") + (bl.reason ? " - " + bl.reason : "") : "No", inline: false },
          { name: "Keys (yours)", value: keys && keys.length ? keys.map((k) => (k.revoked ? "[revoked] " : "") + k.key + " - " + (k.projects?.name || "?")).join("\n").slice(0, 1000) : "None", inline: false },
        );
      return interaction.editReply({ embeds: [embed] });
    }
    if (sub === "blacklist") {
      const reason = interaction.options.getString("reason") || null;
      await supabase.from("blacklist").upsert({ account_id: accountId, discord_id: target.id, reason, banned: false }, { onConflict: "account_id,discord_id" });
      return interaction.editReply({ content: "Blacklisted " + target.username });
    }
    if (sub === "unblacklist") {
      await supabase.from("blacklist").delete().eq("account_id", accountId).eq("discord_id", target.id);
      return interaction.editReply({ content: "Removed blacklist for " + target.username });
    }
    if (sub === "ban") {
      const reason = interaction.options.getString("reason") || null;
      await supabase.from("blacklist").upsert({ account_id: accountId, discord_id: target.id, reason, banned: true }, { onConflict: "account_id,discord_id" });
      await supabase.from("keys").update({ revoked: true }).eq("discord_id", target.id).eq("owner_account_id", accountId);
      return interaction.editReply({ content: "Banned " + target.username + " and revoked all their keys." });
    }
    if (sub === "unban") {
      await supabase.from("blacklist").delete().eq("account_id", accountId).eq("discord_id", target.id);
      return interaction.editReply({ content: "Unbanned " + target.username });
    }
  }

  // ============================================================
  // /hwid reset
  // ============================================================
  async function handleHwidGroup(interaction, sub) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });
    if (sub !== "reset") return;
    const target = interaction.options.getUser("target", true);
    const slug = interaction.options.getString("project");
    const project = await getActiveProject(interaction.user.id, accountId, slug);
    const q = supabase.from("keys").update({ hwid: null, last_hwid_reset: new Date().toISOString() })
      .eq("discord_id", target.id).eq("owner_account_id", accountId);
    if (project) q.eq("project_id", project.id);
    const { data, error } = await q.select("id");
    if (error) return interaction.editReply({ content: "Error: " + error.message });
    interaction.editReply({ content: "Reset HWID on " + (data?.length || 0) + " key(s) for " + target.username });
  }

  // ============================================================
  // /whitelist
  // ============================================================
  async function handleWhitelist(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });
    const target = interaction.options.getUser("target", true);
    const slug = interaction.options.getString("project");
    const project = await getActiveProject(interaction.user.id, accountId, slug);
    if (!project) return interaction.editReply({ content: "No project selected." });

    // Check if user already has a key for this project
    const { data: existing } = await supabase.from("keys")
      .select("key, revoked").eq("discord_id", target.id).eq("project_id", project.id).maybeSingle();
    let keyValue;
    if (existing && !existing.revoked) {
      keyValue = existing.key;
    } else {
      const settings = await getSettings(accountId);
      keyValue = makeKey(settings.key_prefix || "KF");
      const insert = {
        owner_account_id: accountId, project_id: project.id, key: keyValue,
        discord_id: target.id, label: "Whitelist: " + target.username, hwid_locked: true,
      };
      const { error } = await supabase.from("keys").insert(insert);
      if (error) return interaction.editReply({ content: "Error creating key: " + error.message });
    }

    // Grant buyer role if configured
    let roleGranted = false;
    if (interaction.guildId) {
      const { data: br } = await supabase.from("discord_buyer_roles")
        .select("role_id").eq("project_id", project.id).eq("guild_id", interaction.guildId).maybeSingle();
      if (br) {
        try {
          const member = await interaction.guild.members.fetch(target.id);
          await member.roles.add(br.role_id);
          roleGranted = true;
        } catch (e) { /* silent */ }
      }
    }

    interaction.editReply({
      content: "Whitelisted " + target.username + " for **" + project.name + "**." +
        (roleGranted ? " Buyer role granted." : "") +
        "\n\nKey: ```" + keyValue + "```",
    });
  }

  // ============================================================
  // /project group
  // ============================================================
  async function handleProjectGroup(interaction, sub) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });

    if (sub === "create") {
      const name = interaction.options.getString("name", true).trim();
      const note = interaction.options.getString("note") || "";
      const { data, error } = await supabase.from("projects")
        .insert({ owner_account_id: accountId, name, note, slug: makeSlug(name) })
        .select().single();
      if (error) return interaction.editReply({ content: "Error: " + error.message });
      return interaction.editReply({ content: "Created project **" + data.name + "** (slug: `" + data.slug + "`)" });
    }
    if (sub === "delete") {
      const slug = interaction.options.getString("slug", true).trim();
      const { data } = await supabase.from("projects").select("id, name").eq("slug", slug).eq("owner_account_id", accountId).maybeSingle();
      if (!data) return interaction.editReply({ content: "Project not found." });
      await supabase.from("projects").delete().eq("id", data.id);
      return interaction.editReply({ content: "Deleted project " + data.name });
    }
    if (sub === "list") {
      const { data } = await supabase.from("projects").select("name, slug, status, whitelist_only")
        .eq("owner_account_id", accountId).order("created_at", { ascending: false });
      if (!data || data.length === 0) return interaction.editReply({ content: "No projects yet." });
      const lines = data.map((p) => "- **" + p.name + "** `" + p.slug + "` (" + p.status + (p.whitelist_only ? ", whitelist" : "") + ")").join("\n");
      return interaction.editReply({ content: "**Projects:**\n" + lines });
    }
    if (sub === "select") {
      const slug = interaction.options.getString("slug", true).trim();
      const { data } = await supabase.from("projects").select("id, name").eq("slug", slug).eq("owner_account_id", accountId).maybeSingle();
      if (!data) return interaction.editReply({ content: "Project not found." });
      await supabase.from("discord_user_context").upsert({
        discord_id: interaction.user.id, active_project_id: data.id, updated_at: new Date().toISOString(),
      }, { onConflict: "discord_id" });
      return interaction.editReply({ content: "Active project set to **" + data.name + "**" });
    }
  }

  // ============================================================
  // /buyerrole group
  // ============================================================
  async function handleBuyerRoleGroup(interaction, sub) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });
    if (!interaction.guildId) return interaction.editReply({ content: "Must be run in a server." });

    if (sub === "set") {
      const role = interaction.options.getRole("role", true);
      const slug = interaction.options.getString("project");
      const project = await getActiveProject(interaction.user.id, accountId, slug);
      if (!project) return interaction.editReply({ content: "No project selected." });
      await supabase.from("discord_buyer_roles").delete()
        .eq("project_id", project.id).eq("guild_id", interaction.guildId);
      const { error } = await supabase.from("discord_buyer_roles").insert({
        account_id: accountId, project_id: project.id, guild_id: interaction.guildId, role_id: role.id,
      });
      if (error) return interaction.editReply({ content: "Error: " + error.message });
      return interaction.editReply({ content: "Buyer role for **" + project.name + "** set to " + role.name });
    }
    if (sub === "clear") {
      const slug = interaction.options.getString("project");
      const project = await getActiveProject(interaction.user.id, accountId, slug);
      if (!project) return interaction.editReply({ content: "No project selected." });
      await supabase.from("discord_buyer_roles").delete()
        .eq("project_id", project.id).eq("guild_id", interaction.guildId);
      return interaction.editReply({ content: "Buyer role cleared for " + project.name });
    }
    if (sub === "list") {
      const { data } = await supabase.from("discord_buyer_roles")
        .select("role_id, projects(name, slug)")
        .eq("account_id", accountId).eq("guild_id", interaction.guildId);
      if (!data || data.length === 0) return interaction.editReply({ content: "No buyer roles set." });
      const lines = data.map((r) => "- **" + (r.projects?.name || "?") + "** -> <@&" + r.role_id + ">").join("\n");
      return interaction.editReply({ content: "**Buyer roles:**\n" + lines });
    }
  }

  // ============================================================
  // /setscript
  // ============================================================
  async function handleSetScript(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const accountId = await requireLogin(interaction);
    if (!accountId) return;
    if (!await isManagerAllowed(interaction, accountId)) return interaction.editReply({ content: "You lack permission." });
    const scriptSlug = interaction.options.getString("script_id", true).trim();
    const { data: script } = await supabase.from("scripts")
      .select("id, name, project_id, projects!inner(owner_account_id)")
      .eq("slug", scriptSlug).maybeSingle();
    if (!script || script.projects.owner_account_id !== accountId) {
      return interaction.editReply({ content: "Script not found or not yours." });
    }
    await supabase.from("discord_user_context").upsert({
      discord_id: interaction.user.id,
      active_project_id: script.project_id,
      active_script_id: script.id,
      updated_at: new Date().toISOString(),
    }, { onConflict: "discord_id" });
    interaction.editReply({ content: "Active script set to **" + script.name + "**" });
  }


  // ============================================================
  // USER COMMANDS
  // ============================================================

  // /redeem - bind an existing key to Discord
  async function handleRedeem(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const key = interaction.options.getString("key", true).trim();
    const discordId = interaction.user.id;

    const { data: keyRow } = await supabase.from("keys")
      .select("id, revoked, discord_id, project_id, owner_account_id, expires_at, projects(name)")
      .eq("key", key).maybeSingle();

    if (!keyRow) return interaction.editReply({ content: "Invalid key." });
    if (keyRow.revoked) return interaction.editReply({ content: "This key has been revoked." });
    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
      return interaction.editReply({ content: "This key has expired." });
    }

    // Check blacklist
    const bl = await isBlacklisted(keyRow.owner_account_id, discordId);
    if (bl && bl.banned) {
      return interaction.editReply({ content: "You are banned from this service." });
    }

    // Bind
    if (keyRow.discord_id && keyRow.discord_id !== discordId) {
      return interaction.editReply({ content: "This key is already bound to another Discord user." });
    }

    if (!keyRow.discord_id) {
      await supabase.from("keys").update({ discord_id: discordId }).eq("id", keyRow.id);
    }

    // Try to grant buyer role
    let roleMsg = "";
    if (interaction.guildId) {
      const { data: br } = await supabase.from("discord_buyer_roles")
        .select("role_id").eq("project_id", keyRow.project_id).eq("guild_id", interaction.guildId).maybeSingle();
      if (br) {
        try {
          const member = await interaction.guild.members.fetch(discordId);
          await member.roles.add(br.role_id);
          roleMsg = " Buyer role granted.";
        } catch (e) {}
      }
    }

    interaction.editReply({
      content: "Key redeemed for **" + (keyRow.projects?.name || "project") + "**." + roleMsg,
    });
  }

  // /loader - full loader script with user's key if available
  async function handleLoader(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const scriptSlug = interaction.options.getString("script_id", true).trim();
    const discordId = interaction.user.id;

    const { data: script } = await supabase.from("scripts")
      .select("id, name, slug, key_mode, project_id, projects!inner(owner_account_id)")
      .eq("slug", scriptSlug).maybeSingle();

    if (!script) return interaction.editReply({ content: "Script not found." });

    const loaderUrl = PUBLIC_BASE_URL + "/v1/load/" + script.slug;
    let loader;
    if (script.key_mode === "keyless") {
      loader = 'loadstring(game:HttpGet("' + loaderUrl + '"))()';
    } else {
      const { data: keyRow } = await supabase.from("keys")
        .select("key, revoked").eq("discord_id", discordId)
        .eq("project_id", script.project_id)
        .eq("owner_account_id", script.projects.owner_account_id).maybeSingle();
      if (keyRow && !keyRow.revoked) {
        loader = '_G.script_key = "' + keyRow.key + '"\nloadstring(game:HttpGet("' + loaderUrl + '?key=".._G.script_key))()';
      } else {
        loader = '_G.script_key = "YOUR_KEY_HERE"\nloadstring(game:HttpGet("' + loaderUrl + '?key=".._G.script_key))()';
      }
    }

    interaction.editReply({
      content: "Loader for **" + script.name + "**:\n\n```lua\n" + loader + "\n```",
    });
  }

  // /script - just the raw URL
  async function handleScriptCmd(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const scriptSlug = interaction.options.getString("script_id", true).trim();
    const { data: script } = await supabase.from("scripts")
      .select("name, slug").eq("slug", scriptSlug).maybeSingle();
    if (!script) return interaction.editReply({ content: "Script not found." });
    interaction.editReply({
      content: "**" + script.name + "** URL:\n`" + PUBLIC_BASE_URL + "/v1/load/" + script.slug + "`",
    });
  }

  // /resethwid - user's own key HWID reset with cooldown
  async function handleResetHwidCmd(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const scriptSlug = interaction.options.getString("script_id", true).trim();
    const discordId = interaction.user.id;
    const COOLDOWN_MS = 15 * 60 * 60 * 1000;

    const { data: script } = await supabase.from("scripts")
      .select("id, name, project_id, projects!inner(owner_account_id)")
      .eq("slug", scriptSlug).maybeSingle();
    if (!script) return interaction.editReply({ content: "Script not found." });

    const { data: keyRow } = await supabase.from("keys")
      .select("id, hwid, last_hwid_reset, revoked").eq("discord_id", discordId)
      .eq("project_id", script.project_id)
      .eq("owner_account_id", script.projects.owner_account_id).maybeSingle();

    if (!keyRow) return interaction.editReply({ content: "You do not have a key for this script." });
    if (keyRow.revoked) return interaction.editReply({ content: "Your key is revoked." });
    if (!keyRow.hwid) return interaction.editReply({ content: "No HWID bound yet. Nothing to reset." });

    if (keyRow.last_hwid_reset) {
      const elapsed = Date.now() - new Date(keyRow.last_hwid_reset).getTime();
      if (elapsed < COOLDOWN_MS) {
        const remaining = COOLDOWN_MS - elapsed;
        const hours = Math.floor(remaining / 3600000);
        const mins = Math.floor((remaining % 3600000) / 60000);
        return interaction.editReply({ content: "Cooldown active. Try again in " + hours + "h " + mins + "m." });
      }
    }

    await supabase.from("keys").update({ hwid: null, last_hwid_reset: new Date().toISOString() }).eq("id", keyRow.id);
    interaction.editReply({ content: "HWID reset. Next reset in 15 hours." });
  }

  // /claimrole - claim buyer role if key valid
  async function handleClaimRole(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    if (!interaction.guildId) return interaction.editReply({ content: "This command must be run in a server." });
    const scriptSlug = interaction.options.getString("script_id", true).trim();
    const discordId = interaction.user.id;

    const { data: script } = await supabase.from("scripts")
      .select("project_id, name, projects!inner(owner_account_id)")
      .eq("slug", scriptSlug).maybeSingle();
    if (!script) return interaction.editReply({ content: "Script not found." });

    const { data: keyRow } = await supabase.from("keys")
      .select("id, revoked, expires_at").eq("discord_id", discordId)
      .eq("project_id", script.project_id).maybeSingle();
    if (!keyRow) return interaction.editReply({ content: "You do not have a redeemed key for this project." });
    if (keyRow.revoked) return interaction.editReply({ content: "Your key is revoked." });
    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
      return interaction.editReply({ content: "Your key has expired." });
    }

    const { data: br } = await supabase.from("discord_buyer_roles")
      .select("role_id").eq("project_id", script.project_id)
      .eq("guild_id", interaction.guildId).maybeSingle();
    if (!br) return interaction.editReply({ content: "No buyer role configured for this project on this server." });

    try {
      const member = await interaction.guild.members.fetch(discordId);
      await member.roles.add(br.role_id);
      interaction.editReply({ content: "Buyer role granted for **" + script.name + "**." });
    } catch (e) {
      interaction.editReply({ content: "Could not assign role: " + (e.message || "unknown") });
    }
  }

  // /mykey
  async function handleMyKey(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;
    const { data } = await supabase.from("keys")
      .select("key, revoked, expires_at, projects(name)").eq("discord_id", discordId).order("created_at", { ascending: false });
    if (!data || data.length === 0) return interaction.editReply({ content: "You have no redeemed keys." });
    const lines = data.slice(0, 10).map((k) => {
      const status = k.revoked ? " (revoked)" : (k.expires_at && new Date(k.expires_at).getTime() < Date.now() ? " (expired)" : "");
      return "- " + (k.projects?.name || "?") + ": `" + k.key + "`" + status;
    }).join("\n");
    interaction.editReply({ content: "**Your keys:**\n" + lines });
  }

  // /myproject
  async function handleMyProject(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;
    const { data } = await supabase.from("keys")
      .select("projects(name, slug, status)").eq("discord_id", discordId).eq("revoked", false);
    if (!data || data.length === 0) return interaction.editReply({ content: "You have no active keys." });
    const seen = new Set();
    const lines = [];
    data.forEach((k) => {
      if (k.projects && !seen.has(k.projects.slug)) {
        seen.add(k.projects.slug);
        lines.push("- **" + k.projects.name + "** `" + k.projects.slug + "` (" + k.projects.status + ")");
      }
    });
    interaction.editReply({ content: "**Your projects:**\n" + lines.join("\n") });
  }

  // /subscription
  async function handleSubscription(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;
    const scriptSlug = interaction.options.getString("script_id");

    let query = supabase.from("keys")
      .select("key, revoked, expires_at, hwid, projects(name, slug)").eq("discord_id", discordId);
    if (scriptSlug) {
      const { data: script } = await supabase.from("scripts").select("project_id").eq("slug", scriptSlug).maybeSingle();
      if (script) query = query.eq("project_id", script.project_id);
    }
    const { data } = await query;
    if (!data || data.length === 0) return interaction.editReply({ content: "No subscriptions found." });

    const embed = new EmbedBuilder().setColor(0x8b5cf6).setTitle("Your subscriptions");
    data.slice(0, 10).forEach((k) => {
      const status = k.revoked ? "REVOKED" : (k.expires_at && new Date(k.expires_at).getTime() < Date.now() ? "EXPIRED" : "ACTIVE");
      const expiry = k.expires_at ? new Date(k.expires_at).toISOString().slice(0, 10) : "Never";
      embed.addFields({
        name: k.projects?.name || "?",
        value: "Status: " + status + "\nExpires: " + expiry + "\nHWID: " + (k.hwid ? "Bound" : "Not bound"),
        inline: false,
      });
    });
    interaction.editReply({ embeds: [embed] });
  }

  // /profile
  async function handleProfile(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;
    const { data: link } = await supabase.from("discord_users")
      .select("account_id, linked_at, accounts(name, plan)").eq("discord_id", discordId).maybeSingle();
    const { count: keyCount } = await supabase.from("keys")
      .select("id", { count: "exact", head: true }).eq("discord_id", discordId);

    const embed = new EmbedBuilder().setColor(0x8b5cf6).setTitle("Your profile - " + interaction.user.username)
      .addFields(
        { name: "Discord", value: "<@" + discordId + ">", inline: true },
        { name: "Solaries account", value: link ? (link.accounts?.name || "linked") : "Not linked", inline: true },
        { name: "Plan", value: link ? (link.accounts?.plan || "-") : "-", inline: true },
        { name: "Keys held", value: String(keyCount || 0), inline: true },
        { name: "Linked at", value: link ? link.linked_at : "-", inline: true },
      );
    interaction.editReply({ embeds: [embed] });
  }

  // /help
  async function handleHelp(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const isAdmin = interaction.memberPermissions?.has("ManageGuild") ?? false;

    let text = "**User commands** (available to everyone):\n" +
      "`/redeem key:<value>` - Bind a key to your Discord\n" +
      "`/loader script_id:<slug>` - Get loader script with your key\n" +
      "`/script script_id:<slug>` - Get raw loader URL\n" +
      "`/resethwid script_id:<slug>` - Reset your HWID (15h cooldown)\n" +
      "`/claimrole script_id:<slug>` - Claim buyer role\n" +
      "`/mykey` - View your redeemed keys\n" +
      "`/myproject` - View your active projects\n" +
      "`/subscription` - Check key expiry\n" +
      "`/profile` - View your Discord link\n" +
      "`/status` - Service status\n" +
      "`/help` - This message";

    if (isAdmin) {
      text += "\n\n**Admin commands** (Manage Server permission required):\n" +
        "`/login` `/logout` `/whoami` `/panel` `/managerrole` `/stats` `/settings`\n" +
        "`/key create|stock|delete|extend|revoke|info|list`\n" +
        "`/user info|blacklist|unblacklist|ban|unban`\n" +
        "`/hwid reset` `/whitelist`\n" +
        "`/project create|delete|list|select`\n" +
        "`/buyerrole set|clear|list` `/setscript`";
    }

    interaction.editReply({ content: text });
  }

  // /status
  async function handleStatus(interaction) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const start = Date.now();
    let dbOk = true;
    try {
      await supabase.from("accounts").select("id", { count: "exact", head: true }).limit(1);
    } catch (e) { dbOk = false; }
    const latency = Date.now() - start;

    const embed = new EmbedBuilder().setColor(dbOk ? 0x22c55e : 0xef4444).setTitle("Solaries Service Status")
      .addFields(
        { name: "Bot", value: "Online", inline: true },
        { name: "Database", value: dbOk ? "Online" : "Down", inline: true },
        { name: "Latency", value: latency + "ms", inline: true },
        { name: "Bot username", value: botStatus.username || "-", inline: true },
        { name: "Servers", value: String(botStatus.guild_count || 0), inline: true },
        { name: "Started", value: botStatus.started_at || "-", inline: true },
      );
    interaction.editReply({ embeds: [embed] });
  }


  // ============================================================
  // BUTTON: Redeem Key - opens modal for user to paste key
  // ============================================================
  async function handleRedeemButton(interaction, scriptId) {
    const modal = new ModalBuilder()
      .setCustomId("sol_redeemmodal_" + scriptId)
      .setTitle("Redeem Your Key");
    const input = new TextInputBuilder()
      .setCustomId("key_value")
      .setLabel("Enter your key")
      .setStyle(TextInputStyle.Short)
      .setRequired(true)
      .setPlaceholder("KF-XXXX-XXXX-XXXX");
    modal.addComponents(new ActionRowBuilder().addComponents(input));
    await interaction.showModal(modal);
  }

  // ============================================================
  // MODAL SUBMIT: Redeem Key
  // ============================================================
  async function handleRedeemSubmit(interaction, scriptId) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const key = interaction.fields.getTextInputValue("key_value").trim();
    const discordId = interaction.user.id;

    const { data: script } = await supabase.from("scripts")
      .select("id, name, project_id, projects!inner(owner_account_id)")
      .eq("id", scriptId).maybeSingle();
    if (!script) return interaction.editReply({ content: "Script not found." });

    const { data: keyRow } = await supabase.from("keys")
      .select("id, revoked, discord_id, project_id, owner_account_id, expires_at")
      .eq("key", key).maybeSingle();

    if (!keyRow) return interaction.editReply({ content: "Invalid key. Check spelling and try again." });
    if (keyRow.revoked) return interaction.editReply({ content: "This key has been revoked." });
    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
      return interaction.editReply({ content: "This key has expired." });
    }

    // Verify key belongs to this script's project
    if (keyRow.project_id && keyRow.project_id !== script.project_id) {
      return interaction.editReply({ content: "This key is not valid for this script." });
    }

    // Blacklist check
    const bl = await isBlacklisted(keyRow.owner_account_id, discordId);
    if (bl && bl.banned) return interaction.editReply({ content: "You are banned from this service." });

    // Already bound?
    if (keyRow.discord_id && keyRow.discord_id !== discordId) {
      return interaction.editReply({ content: "This key is already bound to another Discord user." });
    }

    // Bind if not already
    if (!keyRow.discord_id) {
      await supabase.from("keys").update({ discord_id: discordId }).eq("id", keyRow.id);
    }

    // Try to auto-grant buyer role
    let roleMsg = "";
    if (interaction.guildId) {
      const { data: br } = await supabase.from("discord_buyer_roles")
        .select("role_id").eq("project_id", script.project_id).eq("guild_id", interaction.guildId).maybeSingle();
      if (br) {
        try {
          const member = await interaction.guild.members.fetch(discordId);
          await member.roles.add(br.role_id);
          roleMsg = "\nBuyer role granted.";
        } catch (e) {}
      }
    }

    interaction.editReply({
      content: "Key redeemed for **" + script.name + "**." + roleMsg + "\n\nClick **Get Script** on the panel to receive your loader.",
    });
  }

  // ============================================================
  // BUTTON: Get Role - claim buyer role if key valid
  // ============================================================
  async function handleGetRoleButton(interaction, scriptId) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    if (!interaction.guildId) return interaction.editReply({ content: "This must be used in a server." });
    const discordId = interaction.user.id;

    const { data: script } = await supabase.from("scripts")
      .select("project_id, name, projects!inner(owner_account_id)")
      .eq("id", scriptId).maybeSingle();
    if (!script) return interaction.editReply({ content: "Script not found." });

    const { data: keyRow } = await supabase.from("keys")
      .select("id, revoked, expires_at").eq("discord_id", discordId)
      .eq("project_id", script.project_id).maybeSingle();
    if (!keyRow) {
      const embed = new EmbedBuilder().setColor(0xef4444).setTitle("No Active License")
        .setDescription("Need an active license to get the role. Redeem a key first.");
      return interaction.editReply({ embeds: [embed] });
    }
    if (keyRow.revoked) {
      const embed = new EmbedBuilder().setColor(0xef4444).setTitle("Key Revoked")
        .setDescription("Your key has been revoked.");
      return interaction.editReply({ embeds: [embed] });
    }
    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
      const embed = new EmbedBuilder().setColor(0xef4444).setTitle("Key Expired")
        .setDescription("Your key has expired.");
      return interaction.editReply({ embeds: [embed] });
    }

    const { data: br } = await supabase.from("discord_buyer_roles")
      .select("role_id").eq("project_id", script.project_id)
      .eq("guild_id", interaction.guildId).maybeSingle();
    if (!br) return interaction.editReply({ content: "No buyer role configured for this project on this server." });

    try {
      const member = await interaction.guild.members.fetch(discordId);
      await member.roles.add(br.role_id);
      interaction.editReply({ content: "Buyer role granted for **" + script.name + "**." });
    } catch (e) {
      interaction.editReply({ content: "Could not assign role: " + (e.message || "unknown") });
    }
  }

  // ============================================================
  // BUTTON: Session Status - show user's key info
  // ============================================================
  async function handleSessionStatus(interaction, scriptId) {
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    const discordId = interaction.user.id;

    const { data: script } = await supabase.from("scripts")
      .select("id, name, project_id, projects!inner(owner_account_id)")
      .eq("id", scriptId).maybeSingle();
    if (!script) return interaction.editReply({ content: "Script not found." });

    const { data: keyRow } = await supabase.from("keys")
      .select("key, revoked, expires_at, hwid, hwid_locked, last_hwid_reset, last_used_at, created_at")
      .eq("discord_id", discordId).eq("project_id", script.project_id).maybeSingle();

    if (!keyRow) {
      const embed = new EmbedBuilder().setColor(0xef4444).setTitle("No Session")
        .setDescription("You do not have a key for **" + script.name + "**. Click Redeem Key to bind one.");
      return interaction.editReply({ embeds: [embed] });
    }

    const status = keyRow.revoked ? "REVOKED" :
      (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now() ? "EXPIRED" : "ACTIVE");
    const statusColor = status === "ACTIVE" ? 0x22c55e : 0xef4444;

    let cooldownInfo = "Available";
    if (keyRow.last_hwid_reset) {
      const elapsed = Date.now() - new Date(keyRow.last_hwid_reset).getTime();
      const COOLDOWN_MS = 15 * 60 * 60 * 1000;
      if (elapsed < COOLDOWN_MS) {
        const remaining = COOLDOWN_MS - elapsed;
        const hours = Math.floor(remaining / 3600000);
        const mins = Math.floor((remaining % 3600000) / 60000);
        cooldownInfo = hours + "h " + mins + "m remaining";
      }
    }

    const maskedKey = keyRow.key.slice(0, 6) + "..." + keyRow.key.slice(-4);
    const embed = new EmbedBuilder().setColor(statusColor).setTitle("Session Status - " + script.name)
      .addFields(
        { name: "Status", value: status, inline: true },
        { name: "Key", value: "`" + maskedKey + "`", inline: true },
        { name: "HWID Locked", value: keyRow.hwid_locked ? "Yes" : "No", inline: true },
        { name: "HWID", value: keyRow.hwid ? "Bound" : "Not bound", inline: true },
        { name: "Reset Cooldown", value: cooldownInfo, inline: true },
        { name: "Expires", value: keyRow.expires_at ? new Date(keyRow.expires_at).toISOString().slice(0, 10) : "Never", inline: true },
        { name: "Last used", value: keyRow.last_used_at || "Never", inline: false },
      );
    interaction.editReply({ embeds: [embed] });
  }


  // ============================================================
  // EXPIRY WARNING SCHEDULER
  // DMs users when their key has ~4 hours left before expiring
  // Runs every 30 minutes
  // ============================================================
  async function checkExpiringKeys() {
    try {
      const now = Date.now();
      const warnStart = new Date(now + 3 * 60 * 60 * 1000).toISOString();
      const warnEnd = new Date(now + 5 * 60 * 60 * 1000).toISOString();

      const { data: expiringKeys } = await supabase.from("keys")
        .select("id, key, discord_id, expires_at, expiry_warned_at, projects(name, slug)")
        .not("discord_id", "is", null)
        .not("expires_at", "is", null)
        .eq("revoked", false)
        .is("expiry_warned_at", null)
        .gte("expires_at", warnStart)
        .lte("expires_at", warnEnd);

      if (!expiringKeys || expiringKeys.length === 0) return;

      for (const k of expiringKeys) {
        const hoursLeft = Math.round((new Date(k.expires_at).getTime() - now) / (60 * 60 * 1000));
        const embed = new EmbedBuilder().setColor(0xf59e0b)
          .setTitle("Key Expiring Soon")
          .setDescription("Your key for **" + (k.projects?.name || "a script") + "** will expire in about " + hoursLeft + " hours.")
          .addFields(
            { name: "Key", value: "`" + k.key.slice(0, 6) + "..." + k.key.slice(-4) + "`", inline: true },
            { name: "Expires", value: new Date(k.expires_at).toISOString(), inline: false },
          )
          .setFooter({ text: "Renew or contact the script owner to extend your access." });

        const sent = await trySendDM(k.discord_id, { embeds: [embed] });
        if (sent) {
          await supabase.from("keys").update({ expiry_warned_at: new Date().toISOString() }).eq("id", k.id);
          console.log("Sent expiry warning DM for key " + k.key.slice(0, 6) + "... to " + k.discord_id);
        }
      }
    } catch (e) {
      console.error("checkExpiringKeys error:", e.message);
    }
  }

  setInterval(checkExpiringKeys, 30 * 60 * 1000);
  setTimeout(checkExpiringKeys, 60 * 1000);

  await client.login(DISCORD_BOT_TOKEN);
}
