import { raise } from "../alerts.js";
import { fetchWithTimeout, nowIso } from "../util.js";

// DNS change detection. Takes a snapshot of each configured record through
// DNS-over-HTTPS and alerts when one changes. Unexpected DNS changes are one
// of the main signs of a domain hijack: an attacker who gets into the
// registrar account repoints the website (A/CNAME), the email (MX), or the
// whole domain (NS).

const TYPE_CODES = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
const RESOLVERS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
const HIGH_RISK = new Set(["NS", "MX", "A", "AAAA", "CNAME"]);

export function fqdn(name, domain) {
  return name === "@" ? domain : `${name}.${domain}`;
}

// Turns a DNS-over-HTTPS JSON answer into a stable string for comparison:
// only records of the asked-for type, normalised, sorted, TTLs ignored.
export function normaliseAnswer(json, type) {
  if (json.Status === 3) return "(none)"; // NXDOMAIN
  if (json.Status !== 0) throw new Error(`DNS lookup failed (status ${json.Status})`);
  const code = TYPE_CODES[type];
  const values = (json.Answer || [])
    .filter((a) => a.type === code)
    .map((a) => {
      let v = String(a.data).trim();
      if (type === "TXT") v = v.replace(/"\s+"/g, "").replace(/^"|"$/g, "");
      else v = v.toLowerCase().replace(/\.$/, "");
      return v;
    })
    .sort();
  return values.length ? values.join(" | ") : "(none)";
}

async function resolve(name, type) {
  let lastErr;
  for (const base of RESOLVERS) {
    try {
      const res = await fetchWithTimeout(`${base}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { Accept: "application/dns-json" } }, 10000);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return normaliseAnswer(await res.json(), type);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

export async function checkDns(env, site) {
  const now = nowIso();
  const results = [];
  for (const [name, type] of site.dns) {
    const host = fqdn(name, site.domain);
    let value;
    try {
      value = await resolve(host, type);
    } catch (err) {
      results.push({ name, type, error: err.message });
      continue; // a failed lookup is not a change — try again next hour
    }
    const prev = await env.DB.prepare("SELECT value FROM dns_snapshots WHERE site_id = ? AND name = ? AND type = ?").bind(site.id, name, type).first();

    if (!prev) {
      // First sighting is the baseline — nothing to compare against yet.
      await env.DB.prepare("INSERT INTO dns_snapshots (site_id, name, type, value, checked_at, changed_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(site.id, name, type, value, now, now)
        .run();
      results.push({ name, type, value, baseline: true });
    } else if (prev.value !== value) {
      await env.DB.batch([
        env.DB.prepare("UPDATE dns_snapshots SET value = ?, checked_at = ?, changed_at = ? WHERE site_id = ? AND name = ? AND type = ?").bind(value, now, now, site.id, name, type),
        env.DB.prepare("INSERT INTO dns_changes (site_id, name, type, old_value, new_value) VALUES (?, ?, ?, ?, ?)").bind(site.id, name, type, prev.value, value),
      ]);
      await raise(env, {
        key: `dns:${site.id}:${name}:${type}:${value}`,
        siteId: site.id,
        severity: HIGH_RISK.has(type) ? "high" : "medium",
        title: `DNS changed: ${type} ${host}`,
        body: `Was: ${prev.value}\nNow: ${value}\n\nIf you (or your host) made this change, acknowledge it on the dashboard. If not, sign in to your registrar now, check the DNS records and change the password — an unexpected ${type} change can mean the domain has been taken over.`,
      });
      results.push({ name, type, value, changed: true });
    } else {
      await env.DB.prepare("UPDATE dns_snapshots SET checked_at = ? WHERE site_id = ? AND name = ? AND type = ?").bind(now, site.id, name, type).run();
      results.push({ name, type, value });
    }
  }
  return results;
}
