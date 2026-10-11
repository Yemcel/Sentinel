import { nowIso } from "./util.js";

// Key/value facts per site (certificate expiry, domain expiry, last errors…).

export async function setFact(env, siteId, key, value) {
  await env.DB.prepare(
    "INSERT INTO site_facts (site_id, key, value, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(site_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  )
    .bind(siteId, key, value, nowIso())
    .run();
}

export async function getFact(env, siteId, key) {
  const row = await env.DB.prepare("SELECT value FROM site_facts WHERE site_id = ? AND key = ?").bind(siteId, key).first();
  return row?.value ?? null;
}

export async function allFacts(env) {
  const rows = (await env.DB.prepare("SELECT site_id, key, value, updated_at FROM site_facts").all()).results;
  const out = {};
  for (const r of rows) (out[r.site_id] ||= {})[r.key] = { value: r.value, updatedAt: r.updated_at };
  return out;
}
