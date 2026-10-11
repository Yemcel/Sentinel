import { overview, overallStatus } from "./data.js";
import { dashboardUrl, sendEmail } from "./alerts.js";
import { HEADER_CHECKS } from "./checks/uptime.js";
import { isoMinutesAgo } from "./util.js";

const pct = (v) => (v == null ? "n/a" : `${(v * 100).toFixed(v === 1 ? 0 : 2)}%`);

export async function buildReport(env) {
  const o = await overview(env);
  const status = overallStatus(o);
  const alerts = (await env.DB.prepare("SELECT severity, title, created_at FROM alerts WHERE created_at >= ? AND severity IN ('medium','high') ORDER BY id DESC LIMIT 15").bind(isoMinutesAgo(1440)).all()).results;

  const lines = [`Sentinel daily report — ${status.text}`, ""];
  for (const s of o.sites) {
    lines.push(s.name.toUpperCase());
    for (const t of s.targets) {
      lines.push(`  ${t.label}: ${t.status.toUpperCase()}  uptime 24h ${pct(t.up24)}, 7d ${pct(t.up7)}${t.lat24 != null ? `, avg ${t.lat24} ms` : ""}${t.headers ? `, security headers ${t.headers.grade}` : ""}`);
    }
    for (const c of s.certs) lines.push(`  Certificate ${c.host}: ${c.days ?? "?"} days left`);
    if (s.domainInfo) lines.push(`  Domain ${s.domain}: ${s.domainDays ?? "?"} days left${s.domain.endsWith(".uk") ? "" : s.domainInfo.transferLocked ? ", transfer lock on" : ", TRANSFER LOCK OFF"}`);
    if (s.dnsLastChange && s.dnsLastChange >= isoMinutesAgo(1440)) lines.push(`  DNS changed in the last 24h (${s.dnsLastChange})`);
    lines.push("");
  }

  lines.push("APP EVENTS (24h)");
  const srcs = Object.entries(o.sources);
  if (!srcs.length) lines.push("  None received");
  for (const [src, c] of srcs) lines.push(`  ${src}: ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`);
  lines.push("");

  lines.push("ALERTS (24h)");
  if (!alerts.length) lines.push("  None");
  for (const a of alerts) lines.push(`  ${a.created_at}  [${a.severity}] ${a.title}`);

  const weak = o.sites.flatMap((s) => s.targets.filter((t) => t.headers?.missing?.length).map((t) => `  ${s.name} ${t.label}: missing ${t.headers.missing.map((k) => HEADER_CHECKS.find((h) => h.key === k)?.label).join(", ")}`));
  if (weak.length) lines.push("", "HARDENING TO DO", ...weak);

  const url = await dashboardUrl(env);
  if (url) lines.push("", `Dashboard: ${url}`);
  return { subject: `[Sentinel] Daily report — ${status.text}`, text: lines.join("\n") };
}

export async function sendDailyReport(env) {
  const r = await buildReport(env);
  await sendEmail(env, r);
  return { sent: true };
}
