import { HEADER_CHECKS } from "./checks/uptime.js";
import { escapeHtml as e } from "./util.js";

// Server-rendered pages. No JavaScript at all, which allows a very strict
// Content-Security-Policy (see index.js): nothing on the page can run
// scripts, even if an attacker got text into an event message.

const fmtTime = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/London", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
export const t = (iso) => (iso ? fmtTime.format(new Date(iso)) : "—");
const pct = (v) => (v == null ? "—" : `${(v * 100).toFixed(v === 1 ? 0 : 2)}%`);
const sev = (s) => `<span class="sev sev-${e(s)}">${e(s)}</span>`;

export function layout(title, body, { refresh = false } = {}) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
${refresh ? '<meta http-equiv="refresh" content="60">' : ""}
<title>${e(title)}</title>
<link rel="stylesheet" href="/app.css">
</head><body>${body}</body></html>`;
}

export function loginPage(message = "") {
  return layout(
    "Sentinel — sign in",
    `<main class="narrow">
  <h1 class="brand">Sentinel</h1>
  <p class="muted">Security and uptime monitoring</p>
  ${message ? `<p class="notice">${e(message)}</p>` : ""}
  <form method="post" action="/login" class="stack">
    <label for="email">Admin email</label>
    <input id="email" name="email" type="email" autocomplete="email" required>
    <button type="submit">Email me a sign-in link</button>
  </form>
  <p class="muted small">No password: a one-time link is emailed to the admin address.</p>
</main>`
  );
}

export function verifyPage(token) {
  return layout(
    "Sentinel — confirm sign in",
    `<main class="narrow">
  <h1 class="brand">Sentinel</h1>
  <form method="post" action="/login/verify" class="stack">
    <input type="hidden" name="t" value="${e(token)}">
    <button type="submit">Sign in</button>
  </form>
  <p class="muted small">This extra click stops email scanners from using up your link.</p>
</main>`
  );
}

function targetRow(tg) {
  return `<tr>
  <td class="nowrap"><span class="dot dot-${e(tg.status)}" aria-hidden="true"></span>${e(tg.label)}</td>
  <td class="status-${e(tg.status)}">${e(tg.status)}</td>
  <td class="num">${tg.latency != null ? `${tg.latency} ms` : "—"}</td>
  <td class="num">${pct(tg.up24)} <span class="muted">/ ${pct(tg.up7)}</span></td>
</tr>${tg.error ? `<tr><td colspan="4" class="err small">${e(tg.error)} · ${t(tg.lastChecked)}</td></tr>` : ""}`;
}

function headersBlock(tg) {
  if (!tg.headers) return "";
  const missing = tg.headers.missing.map((k) => HEADER_CHECKS.find((h) => h.key === k)).filter(Boolean);
  return `<details class="small"><summary>${e(tg.label)} security headers: <strong class="grade grade-${e(tg.headers.grade)}">${e(tg.headers.grade)}</strong>${missing.length ? ` · ${missing.length} missing` : ""}</summary>
  ${missing.length ? `<ul>${missing.map((h) => `<li><strong>${e(h.label)}</strong> — ${e(h.why)}</li>`).join("")}</ul>` : "<p>All six present.</p>"}
</details>`;
}

function siteCard(s) {
  const domainLine = s.domainInfo
    ? `Domain: <strong>${s.domainDays ?? "?"}</strong> days left${s.domain.endsWith(".uk") ? "" : s.domainInfo.transferLocked ? " · transfer lock on" : ' · <span class="err">transfer lock OFF</span>'}${s.domainInfo.registrar ? ` · ${e(s.domainInfo.registrar)}` : ""}`
    : s.domainError
      ? `<span class="err">Domain check failed: ${e(s.domainError)}</span>`
      : "Domain: first check runs at about 6am";
  const certLine = s.certs.length
    ? s.certs.map((c) => `Certificate ${e(c.host)}: <strong class="${c.days != null && c.days < 14 ? "err" : ""}">${c.days ?? "?"}</strong> days`).join("<br>")
    : s.certError
      ? `<span class="err">Certificate check failed: ${e(s.certError)}</span>`
      : "Certificates: first check runs at about 6am";
  return `<section class="card">
  <header class="card-head"><div><h2>${e(s.name)}</h2><span class="muted small">${e(s.domain)}</span></div>
  ${s.openAlerts ? `<span class="pill pill-warn">${s.openAlerts} alert(s)</span>` : ""}</header>
  <table class="tbl"><thead><tr><th>Service</th><th>Status</th><th class="num">Response</th><th class="num">Uptime 24h / 7d</th></tr></thead>
  <tbody>${s.targets.map(targetRow).join("")}</tbody></table>
  ${s.targets.map(headersBlock).join("")}
  <p class="small">${certLine}</p>
  <p class="small">${domainLine}</p>
  <p class="small">DNS: ${s.dnsLastChange ? `last change ${t(s.dnsLastChange)}` : "no changes recorded"}</p>
  <form method="post" action="/run" class="inline"><input type="hidden" name="site" value="${e(s.id)}"><button class="secondary" type="submit">Run all checks now</button></form>
</section>`;
}

export function dashboardPage({ o, status, alerts, events, dnsChanges, flash }) {
  const sourceRows = Object.entries(o.sources)
    .map(([src, c]) => `<tr><td>${e(src)}</td><td class="num">${c.high}</td><td class="num">${c.medium}</td><td class="num">${c.low}</td><td class="num">${c.info}</td></tr>`)
    .join("");
  return layout(
    "Sentinel",
    `<header class="top">
  <div><h1 class="brand">Sentinel</h1><span class="muted small">Updated ${t(new Date().toISOString())} · refreshes every minute</span></div>
  <div class="top-right"><span class="pill pill-${status.level}">${e(status.text)}</span>
  <form method="post" action="/logout" class="inline"><button class="link" type="submit">Sign out</button></form></div>
</header>
<main>
${flash ? `<p class="notice">${e(flash)}</p>` : ""}
<div class="grid">${o.sites.map(siteCard).join("")}</div>

<section class="card">
  <header class="card-head"><h2>Open alerts</h2>
  ${alerts.length ? `<form method="post" action="/ack" class="inline"><input type="hidden" name="id" value="all"><button class="secondary" type="submit">Acknowledge all</button></form>` : ""}</header>
  ${alerts.length ? `<table class="tbl"><thead><tr><th>When</th><th>Severity</th><th>Alert</th><th></th></tr></thead><tbody>
  ${alerts.map((a) => `<tr><td class="nowrap">${t(a.created_at)}</td><td>${sev(a.severity)}</td><td><strong>${e(a.title)}</strong>${a.n > 1 ? ` <span class="muted small">×${a.n}</span>` : ""}${a.body ? `<details class="small"><summary>Details</summary><pre>${e(a.body)}</pre></details>` : ""}</td>
  <td><form method="post" action="/ack" class="inline"><input type="hidden" name="id" value="${a.id}"><button class="secondary" type="submit">Acknowledge</button></form></td></tr>`).join("")}
  </tbody></table>` : `<p class="muted">Nothing needs attention.</p>`}
</section>

<section class="card">
  <h2>App events</h2>
  ${sourceRows ? `<table class="tbl compact"><thead><tr><th>Source (24h)</th><th class="num">High</th><th class="num">Medium</th><th class="num">Low</th><th class="num">Info</th></tr></thead><tbody>${sourceRows}</tbody></table>` : ""}
  ${events.length ? `<table class="tbl"><thead><tr><th>When</th><th>Source</th><th>Event</th><th>Severity</th><th>Account</th><th>Network</th></tr></thead><tbody>
  ${events.map((ev) => `<tr><td class="nowrap">${t(ev.at)}</td><td>${e(ev.source)}</td><td>${e(ev.type)}${ev.message ? `<div class="muted small">${e(ev.message)}</div>` : ""}</td><td>${sev(ev.severity)}</td><td>${e(ev.actor || "")}</td><td class="mono">${e(ev.ip || "")}</td></tr>`).join("")}
  </tbody></table>` : `<p class="muted">No events received yet.</p>`}
</section>

<section class="card">
  <h2>DNS changes</h2>
  ${dnsChanges.length ? `<table class="tbl"><thead><tr><th>When</th><th>Record</th><th>Was</th><th>Now</th></tr></thead><tbody>
  ${dnsChanges.map((d) => `<tr><td class="nowrap">${t(d.at)}</td><td class="mono">${e(d.type)} ${e(d.name)} · ${e(d.site_id)}</td><td class="mono small">${e(d.old_value)}</td><td class="mono small">${e(d.new_value)}</td></tr>`).join("")}
  </tbody></table>` : `<p class="muted">No changes since monitoring began.</p>`}
</section>
</main>
<footer class="muted small">Sentinel · personal data is masked on arrival · checks every 5 minutes</footer>`,
    { refresh: true }
  );
}
