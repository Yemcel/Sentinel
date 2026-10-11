import { ALERT_DEDUPE_MINUTES, DAILY_EMAIL_CAP } from "./config.js";
import { isoMinutesAgo, nowIso } from "./util.js";

// --- Email via Resend ------------------------------------------------------------
export async function sendEmail(env, { subject, text }) {
  const to = env.ADMIN_EMAIL?.trim();
  if (!to) throw new Error("ADMIN_EMAIL is not set");
  if (!env.RESEND_API_KEY) {
    // Local development only: print instead of sending.
    if (env.DEV === "true") {
      console.log(`[dev email] To: ${to}\nSubject: ${subject}\n\n${text}`);
      return { dev: true };
    }
    throw new Error("RESEND_API_KEY is not set");
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.ALERT_FROM || "Sentinel <sentinel@prudencewallet.com>", to: [to], subject, text }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

// --- Alerts --------------------------------------------------------------------------
// raise() records an alert and emails it, unless the same key was alerted in
// the last hour (then it's only recorded) or today's email cap is reached.
// severity: info | low | medium | high. info/low are recorded, not emailed.
export async function raise(env, { key, siteId = null, severity = "medium", title, body = "" }) {
  const recent = await env.DB.prepare("SELECT id FROM alerts WHERE key = ? AND created_at >= ? LIMIT 1")
    .bind(key, isoMinutesAgo(ALERT_DEDUPE_MINUTES))
    .first();
  const { meta } = await env.DB.prepare("INSERT INTO alerts (key, site_id, severity, title, body) VALUES (?, ?, ?, ?, ?)")
    .bind(key, siteId, severity, String(title).slice(0, 200), String(body).slice(0, 4000))
    .run();

  if (recent || severity === "info" || severity === "low") return { emailed: false };

  const today = nowIso().slice(0, 10);
  const sentToday = await env.DB.prepare("SELECT COUNT(*) AS n FROM alerts WHERE emailed = 1 AND created_at >= ?").bind(`${today}T00:00:00Z`).first();
  if (Number(sentToday?.n || 0) >= DAILY_EMAIL_CAP) return { emailed: false, capped: true };

  try {
    const dashboard = await dashboardUrl(env);
    await sendEmail(env, {
      subject: `[Sentinel] ${severity.toUpperCase()}: ${title}`,
      text: `${title}\n\n${body}\n\nSeverity: ${severity}\nTime: ${nowIso()}${dashboard ? `\nDashboard: ${dashboard}` : ""}\n\nThe same alert is emailed at most once an hour.`,
    });
    await env.DB.prepare("UPDATE alerts SET emailed = 1 WHERE id = ?").bind(meta.last_row_id).run();
    return { emailed: true };
  } catch (err) {
    console.error("Alert email failed:", err.message);
    return { emailed: false, error: err.message };
  }
}

// The dashboard's address, remembered from the last time it was opened
// (scheduled runs have no request to read it from).
export async function dashboardUrl(env) {
  const row = await env.DB.prepare("SELECT value FROM site_facts WHERE site_id = 'sentinel' AND key = 'dashboard_url'").first();
  return row?.value || null;
}

// Sentinel's own security events (sign-ins, rejected ingest calls) go into
// the same events table as the apps', under source "sentinel".
export async function selfEvent(env, type, severity, message, ip = null) {
  try {
    await env.DB.prepare("INSERT INTO events (source, type, severity, message, ip, at) VALUES ('sentinel', ?, ?, ?, ?, ?)")
      .bind(type, severity, message, ip, nowIso())
      .run();
  } catch (err) {
    console.error("Self event write failed:", err.message);
  }
}
