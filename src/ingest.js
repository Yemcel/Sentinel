import { RULES } from "./config.js";
import { raise, selfEvent } from "./alerts.js";
import { hit } from "./ratelimit.js";
import { clientIp, isoMinutesAgo, maskEmail, maskIp, nowIso, safeEqual } from "./util.js";

// --- Event ingest (the mini SIEM) -------------------------------------------------------
// Apps send their security events here:
//   POST /api/ingest
//   Authorization: Bearer <that app's token>
//   { "type": "login_failed", "severity": "low", "message": "...", "actor": "a@b.com", "ip": "1.2.3.4" }
// or { "events": [ …up to 50… ] }.
// Each app has its own token (INGEST_TOKENS), so one can be revoked without
// touching the others, and the source of every event is known for certain.
// Emails and IPs are masked on arrival.

const SEVERITIES = new Set(["info", "low", "medium", "high"]);
const MAX_PER_REQUEST = 50;
const SOURCE_LIMIT_PER_HOUR = 2000;

export function parseTokens(raw) {
  return String(raw || "")
    .split(",")
    .map((pair) => pair.trim())
    .filter(Boolean)
    .map((pair) => {
      const i = pair.indexOf(":");
      return { source: pair.slice(0, i).trim(), token: pair.slice(i + 1).trim() };
    })
    .filter((t) => t.source && t.token.length >= 32);
}

export function identifySource(env, request) {
  const auth = request.headers.get("authorization") || "";
  const presented = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!presented) return null;
  let match = null;
  // Compare against every token (no early exit) so timing doesn't reveal which matched.
  for (const t of parseTokens(env.INGEST_TOKENS)) if (safeEqual(presented, t.token)) match = t.source;
  return match;
}

export function cleanEvent(raw) {
  if (!raw || typeof raw !== "object") return null;
  const type = String(raw.type || "").toLowerCase();
  if (!/^[a-z0-9_.-]{1,50}$/.test(type)) return null;
  const severity = SEVERITIES.has(raw.severity) ? raw.severity : "info";
  const parsed = Date.parse(raw.at);
  const at = Number.isFinite(parsed) && Math.abs(parsed - Date.now()) < 86400000 ? new Date(parsed).toISOString().replace(/\.\d{3}Z$/, "Z") : nowIso();
  return {
    type,
    severity,
    message: raw.message ? String(raw.message).slice(0, 500) : null,
    actor: raw.actor ? maskEmail(raw.actor) : null,
    ip: raw.ip ? maskIp(raw.ip) : null,
    at,
  };
}

export async function handleIngest(request, env, ctx) {
  const callerIp = maskIp(clientIp(request));
  const source = identifySource(env, request);
  if (!source) {
    if (!(await hit(env, `ingest-bad:${callerIp}`, 20, 60))) return json({ error: "Too many requests" }, 429);
    await selfEvent(env, "ingest_auth_failed", "medium", "Event sent with a missing or wrong token", callerIp);
    return json({ error: "Unauthorized" }, 401);
  }
  if (!(await hit(env, `ingest:${source}`, SOURCE_LIMIT_PER_HOUR, 60))) return json({ error: "Rate limit reached for this source" }, 429);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Body must be JSON" }, 400);
  }
  const list = Array.isArray(body?.events) ? body.events : [body];
  if (list.length > MAX_PER_REQUEST) return json({ error: `At most ${MAX_PER_REQUEST} events per request` }, 400);
  const events = list.map(cleanEvent).filter(Boolean);
  if (!events.length) return json({ error: "No valid events (each needs a lowercase 'type')" }, 400);

  await env.DB.batch(
    events.map((e) =>
      env.DB.prepare("INSERT INTO events (source, type, severity, message, actor, ip, at) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(source, e.type, e.severity, e.message, e.actor, e.ip, e.at)
    )
  );
  // Rules run after the response is sent, so the app isn't kept waiting.
  ctx.waitUntil(applyRules(env, source, events).catch((err) => console.error("Rules failed:", err.message)));
  return json({ accepted: events.length, rejected: list.length - events.length }, 202);
}

// --- Detection rules ------------------------------------------------------------------------
const isLoginFailure = (type) => /login_failed|signin_failed|auth_failed/.test(type);
const isError = (type) => /error|exception|crash/.test(type);

export async function applyRules(env, source, events) {
  const count = async (sql, ...args) => Number((await env.DB.prepare(sql).bind(...args).first())?.n || 0);

  // 1. Anything an app marks high severity is emailed.
  for (const e of events.filter((e) => e.severity === "high")) {
    await raise(env, { key: `event:${source}:${e.type}`, siteId: source, severity: "high", title: `${source}: ${e.type}`, body: [e.message, e.actor && `Account: ${e.actor}`, e.ip && `Address: ${e.ip}`].filter(Boolean).join("\n") });
  }

  // 2. A burst of failed sign-ins on one app (password guessing).
  if (events.some((e) => isLoginFailure(e.type))) {
    const { count: limit, minutes } = RULES.failedLoginSpike;
    const n = await count("SELECT COUNT(*) AS n FROM events WHERE source = ? AND at >= ? AND (type LIKE '%login_failed%' OR type LIKE '%signin_failed%' OR type LIKE '%auth_failed%')", source, isoMinutesAgo(minutes));
    if (n >= limit) {
      await raise(env, { key: `spike-login:${source}`, siteId: source, severity: "high", title: `${source}: ${n} failed sign-ins in ${minutes} minutes`, body: `Unusually many failed sign-ins — possibly password guessing or credential stuffing. Check the events list on the dashboard for the addresses involved.` });
    }

    // 3. The same network failing sign-ins on two or more of your projects:
    //    someone targeting you specifically, not a random bot.
    const { sources, minutes: m } = RULES.crossProject;
    for (const ip of [...new Set(events.filter((e) => isLoginFailure(e.type) && e.ip).map((e) => e.ip))]) {
      const rows = (await env.DB.prepare("SELECT DISTINCT source FROM events WHERE ip = ? AND at >= ? AND (type LIKE '%login_failed%' OR type LIKE '%signin_failed%' OR type LIKE '%auth_failed%')").bind(ip, isoMinutesAgo(m)).all()).results;
      if (rows.length >= sources) {
        await raise(env, { key: `cross:${ip}`, severity: "high", title: `Same address attacking ${rows.length} projects`, body: `Failed sign-ins from network ${ip} on: ${rows.map((r) => r.source).join(", ")} within ${m} minutes.\nThis looks targeted. Consider blocking the range at your host or firewall.` });
      }
    }
  }

  // 4. A burst of errors (something broken, or someone probing).
  if (events.some((e) => isError(e.type))) {
    const { count: limit, minutes } = RULES.errorSpike;
    const n = await count("SELECT COUNT(*) AS n FROM events WHERE source = ? AND at >= ? AND (type LIKE '%error%' OR type LIKE '%exception%' OR type LIKE '%crash%')", source, isoMinutesAgo(minutes));
    if (n >= limit) {
      await raise(env, { key: `spike-error:${source}`, siteId: source, severity: "high", title: `${source}: ${n} errors in ${minutes} minutes`, body: `Errors are spiking. Check the app's logs.` });
    }
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
