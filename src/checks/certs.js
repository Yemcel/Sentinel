import { CERT_WARN_DAYS } from "../config.js";
import { raise } from "../alerts.js";
import { daysUntil, fetchWithTimeout, nowIso } from "../util.js";
import { setFact, getFact } from "../facts.js";

// TLS certificates, from Certificate Transparency (CT) logs.
//
// Every publicly trusted certificate must be published in CT logs. Watching
// them (here through SSLMate's Cert Spotter API) gives two things:
//   1. Expiry — how long the certificate each site uses has left.
//   2. Mis-issuance detection — if anyone gets a certificate for your domain
//      (e.g. an attacker who briefly controlled your DNS), it shows up here.
//      A certificate from a certificate authority never seen before for the
//      site is flagged.

const API = "https://api.certspotter.com/v1/issuances";

export function covers(host, dnsName) {
  if (dnsName === host) return true;
  if (!dnsName.startsWith("*.")) return false;
  const suffix = dnsName.slice(1); // ".example.com"
  return host.endsWith(suffix) && host.split(".").length === dnsName.split(".").length;
}

export function issuerName(issuance) {
  const i = issuance.issuer || {};
  return i.friendly_name || i.operator?.name || i.name || "unknown";
}

// The hostnames a site serves that are under its own domain (the Render
// backend's onrender.com certificate belongs to Render, not to us).
export function siteHosts(site) {
  return [...new Set(site.targets.map((t) => new URL(t.url).hostname))].filter((h) => h === site.domain || h.endsWith(`.${site.domain}`));
}

async function fetchIssuances(domain, after) {
  const params = new URLSearchParams({ domain, include_subdomains: "true", match_wildcards: "true" });
  params.append("expand", "dns_names");
  params.append("expand", "issuer");
  if (after) params.set("after", after);
  const res = await fetchWithTimeout(`${API}?${params}`, { headers: { "User-Agent": "Sentinel-Monitor/1.0" } }, 20000);
  if (!res.ok) throw new Error(`Cert Spotter ${res.status}: ${(await res.text()).slice(0, 150)}`);
  return res.json();
}

export async function checkCerts(env, site) {
  const lastId = await getFact(env, site.id, "ct_last_id");
  const baseline = !lastId;
  let after = lastId;
  const found = [];
  try {
    for (let page = 0; page < 5; page++) {
      const batch = await fetchIssuances(site.domain, after);
      if (!batch.length) break;
      found.push(...batch);
      after = batch[batch.length - 1].id;
      if (batch.length < 100) break;
    }
    await setFact(env, site.id, "ct_error", null);
  } catch (err) {
    await setFact(env, site.id, "ct_error", err.message);
    return { error: err.message };
  }

  for (const iss of found) {
    const issuer = issuerName(iss);
    const known = await env.DB.prepare("SELECT 1 FROM certificates WHERE site_id = ? AND issuer = ? LIMIT 1").bind(site.id, issuer).first();
    await env.DB.prepare("INSERT OR IGNORE INTO certificates (id, site_id, dns_names, issuer, not_before, not_after) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(String(iss.id), site.id, (iss.dns_names || []).join(", "), issuer, iss.not_before, iss.not_after)
      .run();
    if (baseline) continue;
    const names = (iss.dns_names || []).join(", ");
    if (!known) {
      await raise(env, {
        key: `ct-ca:${site.id}:${issuer}`,
        siteId: site.id,
        severity: "medium",
        title: `New certificate authority for ${site.domain}: ${issuer}`,
        body: `A certificate was issued for ${names} by ${issuer}, a certificate authority not seen before for this site.\n\nThis is expected if you changed hosting or added a service. If not, someone may have obtained a certificate for your domain — check your DNS and registrar account.`,
      });
    } else {
      await raise(env, { key: `ct:${iss.id}`, siteId: site.id, severity: "info", title: `Certificate issued for ${names}`, body: `Issuer: ${issuer}. Valid ${iss.not_before} to ${iss.not_after}.` });
    }
  }
  if (after && after !== lastId) await setFact(env, site.id, "ct_last_id", after);

  // Expiry for each hostname the site serves: the newest valid certificate covering it.
  const certs = (await env.DB.prepare("SELECT dns_names, not_before, not_after FROM certificates WHERE site_id = ?").bind(site.id).all()).results;
  const now = Date.now();
  const expiry = {};
  for (const host of siteHosts(site)) {
    let best = null;
    for (const c of certs) {
      if (Date.parse(c.not_before) > now) continue;
      if (!c.dns_names.split(", ").some((n) => covers(host, n))) continue;
      if (!best || Date.parse(c.not_after) > Date.parse(best)) best = c.not_after;
    }
    expiry[host] = best;
    const days = daysUntil(best);
    if (best && days < CERT_WARN_DAYS) {
      await raise(env, {
        key: `cert-exp:${host}:${days < 7 ? "7" : "14"}`,
        siteId: site.id,
        severity: days < 7 ? "high" : "medium",
        title: `Certificate for ${host} expires in ${days} day(s)`,
        body: `The newest certificate for ${host} expires on ${best}. Certificates normally renew automatically about 30 days before expiry, so automatic renewal may be failing — check the hosting dashboard.`,
      });
    }
  }
  await setFact(env, site.id, "cert_expiry", JSON.stringify(expiry));
  await setFact(env, site.id, "ct_checked_at", nowIso());
  return { baseline, newIssuances: found.length, expiry };
}
