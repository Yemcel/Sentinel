import { sendEmail, selfEvent } from "./alerts.js";
import { hit } from "./ratelimit.js";
import { clientIp, isoMinutesAhead, maskIp, nowIso, randomToken, safeEqual, sha256Hex } from "./util.js";

// --- Dashboard sign-in: passwordless email links ----------------------------------
// There is no password to guess or leak. To sign in you enter the admin
// email; a one-time link (valid 15 minutes) is emailed there. Opening the
// link shows a "Sign in" button — the link itself only works with a POST, so
// email security scanners that open links automatically can't use it up.
//
// Only SHA-256 hashes of link tokens and session ids are stored, so a copy
// of the database can't be used to sign in. Sessions last 12 hours and live
// in an HttpOnly, Secure, SameSite=Strict cookie (not readable by scripts,
// HTTPS only, not sent on requests from other sites).

const LINK_MINUTES = 15;
const SESSION_HOURS = 12;
const COOKIE = "__Host-sentinel"; // __Host- prefix: Secure, Path=/, no Domain — can't be set by subdomains

export async function currentSession(request, env) {
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]+)`));
  if (!m) return null;
  const row = await env.DB.prepare("SELECT id_hash, expires_at FROM sessions WHERE id_hash = ?").bind(await sha256Hex(m[1])).first();
  if (!row || row.expires_at < nowIso()) return null;
  return row;
}

export async function requestLink(request, env, email) {
  const ip = maskIp(clientIp(request));
  // Limits: 5 requests an hour per network; and at most 10 links an hour
  // emailed in total, so the admin inbox can't be flooded. Requests for other
  // emails don't count towards that, so random spam can't lock the admin out.
  if (!(await hit(env, `login-ip:${ip}`, 5, 60))) {
    await selfEvent(env, "login_rate_limited", "medium", "Too many sign-in link requests from one network", ip);
    return { limited: true };
  }
  const admin = (env.ADMIN_EMAIL || "").trim().toLowerCase();
  const given = String(email || "").trim().toLowerCase();
  if (!admin || !safeEqual(given, admin)) {
    await selfEvent(env, "login_wrong_email", "low", "Sign-in link requested for a non-admin email", ip);
    return { ok: true }; // same response either way: don't reveal which email is the admin
  }
  if (!(await hit(env, "login-links", 10, 60))) {
    await selfEvent(env, "login_rate_limited", "medium", "Sign-in link limit reached", ip);
    return { ok: true };
  }
  const token = randomToken();
  await env.DB.prepare("INSERT INTO login_tokens (token_hash, expires_at) VALUES (?, ?)").bind(await sha256Hex(token), isoMinutesAhead(LINK_MINUTES)).run();
  const origin = new URL(request.url).origin;
  await sendEmail(env, {
    subject: "[Sentinel] Your sign-in link",
    text: `Sign in to Sentinel:\n\n${origin}/login/verify?t=${token}\n\nThe link works once and expires in ${LINK_MINUTES} minutes.\nRequested from network ${ip}. If this wasn't you, ignore this email — nobody can sign in without it.`,
  });
  await selfEvent(env, "login_link_sent", "info", "Sign-in link emailed", ip);
  return { ok: true };
}

// Returns a Set-Cookie header value on success, null otherwise.
export async function redeemLink(request, env, token) {
  const ip = maskIp(clientIp(request));
  if (!(await hit(env, `verify-ip:${ip}`, 10, 60))) return null;
  const hash = await sha256Hex(String(token || ""));
  const row = await env.DB.prepare("SELECT expires_at, used_at FROM login_tokens WHERE token_hash = ?").bind(hash).first();
  if (!row || row.used_at || row.expires_at < nowIso()) {
    await selfEvent(env, "login_failed", "low", row ? "Expired or already-used sign-in link" : "Invalid sign-in link", ip);
    return null;
  }
  // Mark used first; the conditional update means two simultaneous attempts can't both succeed.
  const { meta } = await env.DB.prepare("UPDATE login_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL").bind(nowIso(), hash).run();
  if (!meta.changes) return null;

  const sid = randomToken();
  await env.DB.prepare("INSERT INTO sessions (id_hash, expires_at, ip) VALUES (?, ?, ?)").bind(await sha256Hex(sid), isoMinutesAhead(SESSION_HOURS * 60), ip).run();
  await selfEvent(env, "login_success", "info", "Signed in to the dashboard", ip);
  return `${COOKIE}=${sid}; Path=/; Max-Age=${SESSION_HOURS * 3600}; HttpOnly; Secure; SameSite=Strict`;
}

export async function signOut(request, env) {
  const s = await currentSession(request, env);
  if (s) await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(s.id_hash).run();
  return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

// Form posts must come from the dashboard itself (CSRF defence on top of
// SameSite=Strict).
// Browsers send Sec-Fetch-Site on every request and pages can't fake it;
// Origin is the fallback for older browsers. (Browsers send "Origin: null"
// in some privacy modes, so Origin alone isn't enough.)
export function sameOrigin(request) {
  const site = request.headers.get("sec-fetch-site");
  if (site) return site === "same-origin";
  return request.headers.get("origin") === new URL(request.url).origin;
}
