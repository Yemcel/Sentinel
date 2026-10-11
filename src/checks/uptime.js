import { DOWN_AFTER_FAILURES, REQUEST_TIMEOUT_MS } from "../config.js";
import { raise } from "../alerts.js";
import { fetchWithTimeout, nowIso } from "../util.js";

// --- Security headers --------------------------------------------------------------
// The six response headers most security scanners look for. Each one turns
// on a browser protection; missing ones are listed on the dashboard.
export const HEADER_CHECKS = [
  { key: "hsts", label: "Strict-Transport-Security", why: "forces HTTPS on return visits", test: (h) => h.has("strict-transport-security") },
  { key: "csp", label: "Content-Security-Policy", why: "limits where scripts can load from (XSS defence)", test: (h) => h.has("content-security-policy") },
  { key: "nosniff", label: "X-Content-Type-Options", why: "stops browsers guessing file types", test: (h) => /nosniff/i.test(h.get("x-content-type-options") || "") },
  {
    key: "framing",
    label: "X-Frame-Options or CSP frame-ancestors",
    why: "stops the site being framed (clickjacking)",
    test: (h) => h.has("x-frame-options") || /frame-ancestors/i.test(h.get("content-security-policy") || ""),
  },
  { key: "referrer", label: "Referrer-Policy", why: "limits what URLs leak to other sites", test: (h) => h.has("referrer-policy") },
  { key: "permissions", label: "Permissions-Policy", why: "switches off camera, mic etc. the site doesn't use", test: (h) => h.has("permissions-policy") },
];

export function gradeHeaders(headers) {
  const present = HEADER_CHECKS.filter((c) => c.test(headers)).map((c) => c.key);
  const score = present.length;
  const grade = score === 6 ? "A" : score === 5 ? "B" : score === 4 ? "C" : score === 3 ? "D" : score >= 1 ? "E" : "F";
  return { present, missing: HEADER_CHECKS.filter((c) => !present.includes(c.key)).map((c) => c.key), grade };
}

// A redirect to another domain (outside the site's own) can mean a hijacked
// site or DNS. Subdomains of the site's domain are fine.
export function redirectedOffsite(originalUrl, finalUrl, siteDomain) {
  const from = new URL(originalUrl).hostname;
  const to = new URL(finalUrl).hostname;
  if (to === from) return false;
  return !(to === siteDomain || to.endsWith(`.${siteDomain}`));
}

// --- One target ----------------------------------------------------------------------
export async function probe(target) {
  const started = Date.now();
  try {
    const res = await fetchWithTimeout(
      target.url,
      { redirect: "follow", headers: { "User-Agent": "Sentinel-Monitor/1.0 (+uptime check)" }, cf: { cacheTtl: 0 } },
      REQUEST_TIMEOUT_MS
    );
    const body = await res.text();
    const latency = Date.now() - started;
    const finalUrl = res.url || target.url;
    const problems = [];
    if (!res.ok) problems.push(`HTTP ${res.status}`);
    if (target.expect && !body.toLowerCase().includes(target.expect.toLowerCase())) problems.push(`expected text "${target.expect}" not found`);
    if (redirectedOffsite(target.url, finalUrl, target.site.domain)) problems.push(`redirected to another site: ${new URL(finalUrl).hostname}`);
    return {
      ok: problems.length === 0,
      statusCode: res.status,
      latency,
      finalUrl,
      error: problems.join("; ") || null,
      // Only grade a healthy response: an error page from a proxy has its own
      // headers and would look like a regression.
      headers: target.html && problems.length === 0 ? gradeHeaders(res.headers) : null,
    };
  } catch (err) {
    const msg = String(err?.message || err);
    return { ok: false, statusCode: null, latency: Date.now() - started, finalUrl: null, error: /abort|timeout/i.test(msg) ? `no response within ${REQUEST_TIMEOUT_MS / 1000}s` : msg.slice(0, 200), headers: null };
  }
}

// Checks every target together. If all of them fail at once — sites on
// different hosts — the problem is far more likely to be Sentinel's own
// network than every site going down, so one "can't reach anything" alert is
// sent instead of a down alert per site, and site states are left alone.
export async function checkAllTargets(env, targets) {
  const results = await Promise.all(targets.map((t) => probe(t)));
  if (targets.length > 1 && results.every((r) => !r.ok)) {
    await env.DB.batch(
      targets.map((t, i) => env.DB.prepare("INSERT INTO checks (target_id, ok, status_code, latency_ms, error) VALUES (?, 0, ?, ?, ?)").bind(t.id, results[i].statusCode, results[i].latency, `(all targets failed) ${results[i].error}`))
    );
    await raise(env, {
      key: "all-unreachable",
      severity: "medium",
      title: "Sentinel can't reach any site",
      body: `All ${targets.length} checks failed at the same time, which usually means a problem on Sentinel's side (Cloudflare network) rather than every site being down. Check one site yourself to be sure.\n\n${targets.map((t, i) => `${t.url}: ${results[i].error}`).join("\n")}`,
    });
    return results;
  }
  return Promise.all(targets.map((t, i) => checkTarget(env, t, results[i])));
}

export async function checkTarget(env, target, probed = null) {
  const result = probed || (await probe(target));
  const prev = (await env.DB.prepare("SELECT * FROM targets WHERE id = ?").bind(target.id).first()) || { status: "unknown", fail_count: 0 };
  const now = nowIso();
  const name = `${target.site.name} ${target.label}`;

  let status = prev.status;
  let failCount = result.ok ? 0 : Number(prev.fail_count || 0) + 1;
  let lastChange = prev.last_change || now;

  if (result.ok && prev.status !== "up") {
    if (prev.status === "down") {
      await raise(env, { key: `up:${target.id}:${now}`, siteId: target.site.id, severity: "medium", title: `Back up: ${name}`, body: `${target.url} is responding again (HTTP ${result.statusCode}, ${result.latency} ms). It was down since ${prev.last_change}.` });
    }
    status = "up";
    lastChange = now;
  } else if (!result.ok && failCount >= DOWN_AFTER_FAILURES && prev.status !== "down") {
    status = "down";
    lastChange = now;
    await raise(env, { key: `down:${target.id}`, siteId: target.site.id, severity: "high", title: `Down: ${name}`, body: `${target.url} failed ${failCount} checks in a row.\nLatest problem: ${result.error}` });
  }

  // Security header regression: a protection that was there last time and has gone.
  if (result.headers && prev.headers_json) {
    const before = JSON.parse(prev.headers_json).present || [];
    const lost = before.filter((k) => !result.headers.present.includes(k));
    if (lost.length) {
      await raise(env, { key: `headers:${target.id}:${lost.join(",")}`, siteId: target.site.id, severity: "medium", title: `Security headers removed: ${name}`, body: `These protections were present before and are now missing: ${lost.join(", ")}.\nThis usually follows a deploy or hosting change.` });
    }
  }

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO targets (id, status, fail_count, last_checked, last_change, last_status_code, last_latency_ms, last_error, final_url, headers_json, headers_grade)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
       ON CONFLICT(id) DO UPDATE SET status = ?2, fail_count = ?3, last_checked = ?4, last_change = ?5, last_status_code = ?6,
         last_latency_ms = ?7, last_error = ?8, final_url = COALESCE(?9, final_url),
         headers_json = COALESCE(?10, headers_json), headers_grade = COALESCE(?11, headers_grade)`
    ).bind(
      target.id, status, failCount, now, lastChange, result.statusCode, result.latency, result.error, result.finalUrl,
      result.headers ? JSON.stringify(result.headers) : null, result.headers?.grade ?? null
    ),
    env.DB.prepare("INSERT INTO checks (target_id, ok, status_code, latency_ms, error) VALUES (?, ?, ?, ?, ?)").bind(
      target.id, result.ok ? 1 : 0, result.statusCode, result.latency, result.error
    ),
  ]);
  return { target: target.id, ...result, status };
}
