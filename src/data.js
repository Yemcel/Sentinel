import { SITES } from "./config.js";
import { allFacts } from "./facts.js";
import { daysUntil, isoMinutesAgo } from "./util.js";

// Everything the dashboard and the daily report show, in one place.
export async function overview(env) {
  const [targets, uptime, facts, dnsChanges, openAlerts, eventCounts] = await Promise.all([
    env.DB.prepare("SELECT * FROM targets").all().then((r) => r.results),
    env.DB.prepare(
      `SELECT target_id,
         SUM(CASE WHEN at >= ?1 THEN ok ELSE 0 END) * 1.0 / NULLIF(SUM(CASE WHEN at >= ?1 THEN 1 ELSE 0 END), 0) AS up24,
         SUM(ok) * 1.0 / COUNT(*) AS up7,
         AVG(CASE WHEN at >= ?1 AND ok = 1 THEN latency_ms END) AS lat24
       FROM checks WHERE at >= ?2 GROUP BY target_id`
    ).bind(isoMinutesAgo(1440), isoMinutesAgo(7 * 1440)).all().then((r) => r.results),
    allFacts(env),
    env.DB.prepare("SELECT site_id, MAX(at) AS last FROM dns_changes GROUP BY site_id").all().then((r) => r.results),
    env.DB.prepare("SELECT site_id, severity, COUNT(*) AS n FROM alerts WHERE acknowledged_at IS NULL AND severity IN ('medium','high') GROUP BY site_id, severity").all().then((r) => r.results),
    env.DB.prepare("SELECT source, severity, COUNT(*) AS n FROM events WHERE at >= ? GROUP BY source, severity").bind(isoMinutesAgo(1440)).all().then((r) => r.results),
  ]);

  const sites = SITES.map((site) => {
    const f = facts[site.id] || {};
    const domain = f.domain?.value ? JSON.parse(f.domain.value) : null;
    const certExpiry = f.cert_expiry?.value ? JSON.parse(f.cert_expiry.value) : {};
    return {
      ...site,
      targets: site.targets.map((t) => {
        const state = targets.find((x) => x.id === t.id) || {};
        const u = uptime.find((x) => x.target_id === t.id) || {};
        return {
          ...t,
          status: state.status || "unknown",
          lastChecked: state.last_checked,
          lastChange: state.last_change,
          statusCode: state.last_status_code,
          latency: state.last_latency_ms,
          error: state.last_error,
          headers: state.headers_json ? JSON.parse(state.headers_json) : null,
          up24: u.up24 == null ? null : Number(u.up24),
          up7: u.up7 == null ? null : Number(u.up7),
          lat24: u.lat24 == null ? null : Math.round(Number(u.lat24)),
        };
      }),
      certs: Object.entries(certExpiry).map(([host, expires]) => ({ host, expires, days: daysUntil(expires) })),
      certError: f.ct_error?.value || null,
      certCheckedAt: f.ct_checked_at?.value || null,
      domainInfo: domain,
      domainDays: domain ? daysUntil(domain.expires) : null,
      domainError: f.rdap_error?.value || null,
      dnsLastChange: dnsChanges.find((d) => d.site_id === site.id)?.last || null,
      openAlerts: openAlerts.filter((a) => a.site_id === site.id).reduce((s, a) => s + Number(a.n), 0),
    };
  });

  const sources = {};
  for (const r of eventCounts) (sources[r.source] ||= { info: 0, low: 0, medium: 0, high: 0 })[r.severity] = Number(r.n);

  return { sites, sources, openAlertsTotal: openAlerts.reduce((s, a) => s + Number(a.n), 0) };
}

export function overallStatus(o) {
  const down = o.sites.flatMap((s) => s.targets).filter((t) => t.status === "down").length;
  if (down) return { level: "bad", text: `${down} service(s) down` };
  if (o.openAlertsTotal) return { level: "warn", text: `${o.openAlertsTotal} open alert(s)` };
  return { level: "good", text: "All systems normal" };
}
