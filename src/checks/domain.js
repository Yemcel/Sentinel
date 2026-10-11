import { DOMAIN_WARN_DAYS } from "../config.js";
import { raise } from "../alerts.js";
import { daysUntil, fetchWithTimeout, nowIso } from "../util.js";
import { getFact, setFact } from "../facts.js";

// Domain registration, from RDAP (the modern replacement for WHOIS).
// Watches for:
//   - expiry: a lapsed domain can be bought by anyone, along with its email
//     (exactly how touch2finish.net was once lost and re-registered);
//   - the registrar transfer lock being removed, which is a step in stealing
//     a domain (.uk domains don't use this lock, so it's not checked there).

// The registry's own RDAP server for each top-level domain. rdap.org (a
// redirect service) refuses requests from cloud hosts such as Cloudflare
// Workers, so known registries are asked directly; rdap.org is only the
// fallback for anything else.
const RDAP_SERVERS = {
  com: "https://rdap.verisign.com/com/v1/",
  net: "https://rdap.verisign.com/net/v1/",
  uk: "https://rdap.nominet.uk/uk/",
};

export function rdapUrl(domain) {
  const tld = domain.split(".").pop().toLowerCase();
  return `${RDAP_SERVERS[tld] || "https://rdap.org/"}domain/${domain}`;
}

export function parseRdap(json) {
  const eventDate = (action) => (json.events || []).find((e) => e.eventAction === action)?.eventDate || null;
  const registrar = (json.entities || []).find((e) => (e.roles || []).includes("registrar"));
  const fn = registrar?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] || registrar?.handle || null;
  const status = (json.status || []).map((s) => String(s).toLowerCase());
  return {
    expires: eventDate("expiration"),
    registered: eventDate("registration"),
    lastChanged: eventDate("last changed"),
    registrar: fn,
    status,
    transferLocked: status.some((s) => s.includes("transfer prohibited")),
    nameservers: (json.nameservers || []).map((n) => String(n.ldhName || "").toLowerCase()).sort(),
  };
}

export async function checkDomain(env, site) {
  let info;
  try {
    const res = await fetchWithTimeout(
      rdapUrl(site.domain),
      { headers: { Accept: "application/rdap+json", "User-Agent": "Sentinel-Monitor/1.0 (domain expiry check)" }, redirect: "follow" },
      20000
    );
    if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
    info = parseRdap(await res.json());
    await setFact(env, site.id, "rdap_error", null);
  } catch (err) {
    await setFact(env, site.id, "rdap_error", err.message);
    return { error: err.message };
  }

  const days = daysUntil(info.expires);
  if (days !== null) {
    const bucket = DOMAIN_WARN_DAYS.filter((d) => days <= d).pop(); // smallest threshold reached
    if (bucket !== undefined) {
      await raise(env, {
        key: `domain-exp:${site.domain}:${bucket}:${info.expires}`,
        siteId: site.id,
        severity: days <= 7 ? "high" : "medium",
        title: `${site.domain} expires in ${days} day(s)`,
        body: `Registration expires ${info.expires} (registrar: ${info.registrar || "unknown"}). Renew it, and turn on auto-renew. If it lapses, anyone can register it and receive its email.`,
      });
    }
  }

  const isUk = site.domain.endsWith(".uk");
  const wasLocked = await getFact(env, site.id, "transfer_locked");
  if (!isUk && wasLocked === "1" && !info.transferLocked) {
    await raise(env, {
      key: `domain-unlock:${site.domain}`,
      siteId: site.id,
      severity: "high",
      title: `Transfer lock removed on ${site.domain}`,
      body: `The registrar transfer lock is no longer set. Unlocking is the first step of moving a domain to another registrar. If you didn't do this, sign in to your registrar now, re-enable the lock and change your password.`,
    });
  }

  await setFact(env, site.id, "domain", JSON.stringify(info));
  await setFact(env, site.id, "transfer_locked", isUk ? null : info.transferLocked ? "1" : "0");
  await setFact(env, site.id, "domain_checked_at", nowIso());
  return info;
}
