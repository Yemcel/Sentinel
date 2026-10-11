// End-to-end test: runs the real Worker in Miniflare (the local Workers
// runtime) with a local D1 database and every outside service mocked.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const TOKEN_A = "token-for-prudence-0123456789abcdefghijkl";
const TOKEN_B = "token-for-listithub-0123456789abcdefghijk";
const ADMIN = "owner@example.com";

// --- Mocked outside world ---------------------------------------------------------
const world = {
  backendUp: true,
  allDown: false,
  dns: { "prudencewallet.com|A": ["216.24.57.1"] },
  certs: [{ id: "100", dns_names: ["www.prudencewallet.com"], issuer: { friendly_name: "Let's Encrypt" }, not_before: "2026-09-01T00:00:00Z", not_after: "2026-11-30T00:00:00Z" }],
  domainExpires: new Date(Date.now() + 20 * 86400000).toISOString(),
  domainStatus: ["client transfer prohibited"],
  emails: [],
};
const typeCodes = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
const j = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } });

async function outbound(request) {
  const url = new URL(request.url);
  if (url.hostname === "api.resend.com") {
    world.emails.push(await request.json());
    return j({ id: "email_1" });
  }
  if (world.allDown) return new Response("bad gateway", { status: 502 });
  switch (url.hostname) {
    case "www.prudencewallet.com":
      return new Response("<html><title>Prudence Wallet</title></html>", { headers: { "Content-Type": "text/html", "Strict-Transport-Security": "max-age=1" } });
    case "prudence-wallet.onrender.com":
      return world.backendUp ? j({ ok: true }) : new Response("down", { status: 503 });
    case "www.listithub.com":
    case "touch2finish.co.uk":
      return new Response("<html>ok</html>", { headers: { "Content-Type": "text/html" } });
    case "cloudflare-dns.com": {
      const name = url.searchParams.get("name");
      const type = url.searchParams.get("type");
      const values = world.dns[`${name}|${type}`] || [];
      return j({ Status: 0, Answer: values.map((data) => ({ name, type: typeCodes[type], TTL: 300, data })) });
    }
    case "api.certspotter.com": {
      const afterId = url.searchParams.get("after");
      const domain = url.searchParams.get("domain");
      const list = domain === "prudencewallet.com" ? world.certs.filter((c) => !afterId || Number(c.id) > Number(afterId)) : [];
      return j(list);
    }
    case "rdap.org":
    case "rdap.verisign.com":
    case "rdap.nominet.uk":
      return j({ events: [{ eventAction: "expiration", eventDate: world.domainExpires }], status: world.domainStatus, entities: [], nameservers: [] });
  }
  return new Response("not mocked", { status: 599 });
}

// --- Runtime ----------------------------------------------------------------------------
let mf;
before(async () => {
  const bundle = await build({ entryPoints: ["src/index.js"], bundle: true, format: "esm", write: false, platform: "neutral" });
  // Miniflare 5 takes a new options shape; convert from the familiar v4 one.
  mf = new Miniflare(convertV4MiniflareOptions({
    modules: [{ type: "ESModule", path: "index.mjs", contents: bundle.outputFiles[0].text }],
    compatibilityDate: "2026-09-01",
    d1Databases: { DB: "test-db" },
    bindings: { ADMIN_EMAIL: ADMIN, RESEND_API_KEY: "re_test", INGEST_TOKENS: `prudence-wallet:${TOKEN_A},listithub:${TOKEN_B}`, ALERT_FROM: "Sentinel <s@example.com>" },
    outboundService: outbound,
  }));
  const db = await mf.getD1Database("DB");
  const sql = readFileSync("migrations/0001_init.sql", "utf8").replace(/--.*$/gm, "");
  for (const stmt of sql.split(";").map((s) => s.trim()).filter(Boolean)) await db.prepare(stmt).run();
});
after(() => mf?.dispose());

const tick = async (iso) => (await mf.getWorker()).scheduled({ scheduledTime: new Date(iso), cron: "*/5 * * * *" });
const db = () => mf.getD1Database("DB");
const lastEmail = () => world.emails[world.emails.length - 1];
const subjects = () => world.emails.map((e) => e.subject);
const settle = () => new Promise((r) => setTimeout(r, 300)); // waitUntil work

// --- Tests --------------------------------------------------------------------------------
test("all targets come up, no emails", async () => {
  await tick("2026-10-05T12:00:00Z");
  const rows = (await (await db()).prepare("SELECT id, status, headers_grade FROM targets ORDER BY id").all()).results;
  assert.deepEqual(rows.map((r) => r.status), ["up", "up", "up", "up"]);
  assert.equal(rows.find((r) => r.id === "prudence-web").headers_grade, "E"); // only HSTS
  assert.equal(world.emails.length, 0);
});

test("backend down after two failures, then recovers", async () => {
  world.backendUp = false;
  await tick("2026-10-05T12:10:00Z");
  assert.equal(world.emails.length, 0, "one failure is not enough");
  await tick("2026-10-05T12:20:00Z");
  assert.match(lastEmail().subject, /HIGH: Down: Prudence Wallet Backend/);
  world.backendUp = true;
  await tick("2026-10-05T12:30:00Z");
  assert.match(lastEmail().subject, /Back up: Prudence Wallet Backend/);
});

test("everything failing at once is one 'can't reach' alert", async () => {
  const before = world.emails.length;
  world.allDown = true;
  await tick("2026-10-05T12:40:00Z");
  await tick("2026-10-05T12:50:00Z");
  world.allDown = false;
  const fresh = subjects().slice(before);
  assert.equal(fresh.length, 1);
  assert.match(fresh[0], /can't reach any site/);
  const down = (await (await db()).prepare("SELECT COUNT(*) AS n FROM targets WHERE status = 'down'").first()).n;
  assert.equal(down, 0);
});

test("DNS baseline then change detection", async () => {
  await tick("2026-10-05T13:05:00Z"); // slot 1 = prudence DNS baseline
  const before = world.emails.length;
  assert.equal((await (await db()).prepare("SELECT value FROM dns_snapshots WHERE site_id='prudence' AND name='@' AND type='A'").first()).value, "216.24.57.1");
  world.dns["prudencewallet.com|A"] = ["6.6.6.6"];
  await tick("2026-10-05T14:05:00Z");
  assert.equal(world.emails.length, before + 1);
  assert.match(lastEmail().subject, /HIGH: DNS changed: A prudencewallet.com/);
  assert.match(lastEmail().text, /Was: 216.24.57.1\nNow: 6.6.6.6/);
});

test("certificates: baseline, expiry, new certificate authority", async () => {
  await tick("2026-10-06T05:00:00Z"); // daily slot 0 = prudence certs
  const exp = JSON.parse((await (await db()).prepare("SELECT value FROM site_facts WHERE site_id='prudence' AND key='cert_expiry'").first()).value);
  assert.equal(exp["www.prudencewallet.com"], "2026-11-30T00:00:00Z");
  const before = world.emails.length;
  world.certs.push({ id: "101", dns_names: ["www.prudencewallet.com"], issuer: { friendly_name: "Shady CA" }, not_before: "2026-10-06T00:00:00Z", not_after: "2027-01-01T00:00:00Z" });
  await tick("2026-10-07T05:00:00Z");
  assert.equal(world.emails.length, before + 1);
  assert.match(lastEmail().subject, /New certificate authority for prudencewallet.com: Shady CA/);
});

test("domain expiry warning and transfer-lock removal", async () => {
  const before = world.emails.length;
  await tick("2026-10-06T05:05:00Z"); // daily slot 1 = prudence domain
  assert.match(lastEmail().subject, /prudencewallet.com expires in (19|20) day/);
  world.domainStatus = ["active"];
  await tick("2026-10-07T05:05:00Z");
  assert.ok(subjects().slice(before).some((s) => /HIGH: Transfer lock removed on prudencewallet.com/.test(s)));
});

test("ingest: authentication, validation, masking", async () => {
  const send = (token, body) => mf.dispatchFetch("https://sentinel.test/api/ingest", { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  assert.equal((await send("wrong-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxx", { type: "x" })).status, 401);
  assert.equal((await send(TOKEN_A, { type: "Bad Type" })).status, 400);
  const ok = await send(TOKEN_A, { events: [{ type: "signup", actor: "someone@gmail.com", ip: "81.2.69.142" }] });
  assert.equal(ok.status, 202);
  const ev = await (await db()).prepare("SELECT source, actor, ip FROM events WHERE type = 'signup'").first();
  assert.deepEqual(ev, { source: "prudence-wallet", actor: "so***@gmail.com", ip: "81.2.69.x" });
  const self = await (await db()).prepare("SELECT COUNT(*) AS n FROM events WHERE source = 'sentinel' AND type = 'ingest_auth_failed'").first();
  assert.equal(self.n, 1);
});

test("ingest rules: high severity, cross-project attacker, login spike", async () => {
  const send = (token, body) => mf.dispatchFetch("https://sentinel.test/api/ingest", { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  let before = world.emails.length;
  await send(TOKEN_A, { type: "jobs_auth_failed", severity: "high", message: "bad secret" });
  await settle();
  assert.match(lastEmail().subject, /HIGH: prudence-wallet: jobs_auth_failed/);

  before = world.emails.length;
  await send(TOKEN_A, { type: "login_failed", severity: "low", ip: "203.0.113.7" });
  await send(TOKEN_B, { type: "login_failed", severity: "low", ip: "203.0.113.99" });
  await settle();
  assert.ok(subjects().slice(before).some((s) => /Same address attacking 2 projects/.test(s)));

  before = world.emails.length;
  await send(TOKEN_B, { events: Array.from({ length: 30 }, () => ({ type: "login_failed", severity: "low", ip: "198.51.100.1" })) });
  await settle();
  assert.ok(subjects().slice(before).some((s) => /listithub: \d+ failed sign-ins in 15 minutes/.test(s)));
});

test("dashboard sign-in flow and protections", async () => {
  const origin = "https://sentinel.test";
  const go = (path, init = {}) => mf.dispatchFetch(origin + path, { redirect: "manual", ...init });

  let r = await go("/");
  assert.equal(r.status, 303);
  assert.equal(r.headers.get("location"), "/login");
  assert.match(r.headers.get("content-security-policy"), /default-src 'none'/);

  const formBody = (o) => new URLSearchParams(o).toString();
  const post = (path, body, extra = {}) => go(path, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin, ...extra }, body: formBody(body) });

  r = await go("/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://evil.example" }, body: formBody({ email: ADMIN }) });
  assert.equal(r.status, 403, "cross-site form post refused");

  const before = world.emails.length;
  r = await post("/login", { email: "attacker@example.com" });
  assert.equal(r.headers.get("location"), "/login?m=sent", "same answer for a wrong email");
  assert.equal(world.emails.length, before, "but no email sent");

  // Real browsers: Sec-Fetch-Site decides, even when Origin is "null".
  r = await go("/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "null", "Sec-Fetch-Site": "cross-site" }, body: formBody({ email: ADMIN }) });
  assert.equal(r.status, 403, "cross-site browser post refused");
  r = await go("/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "null", "Sec-Fetch-Site": "same-origin" }, body: formBody({ email: "nobody@example.com" }) });
  assert.equal(r.headers.get("location"), "/login?m=sent", "same-origin browser post accepted with Origin: null");

  r = await post("/login", { email: ADMIN.toUpperCase() });
  assert.match(lastEmail().subject, /sign-in link/);
  const token = lastEmail().text.match(/verify\?t=([A-Za-z0-9_-]+)/)[1];

  r = await go(`/login/verify?t=${token}`);
  assert.equal(r.status, 200, "GET shows a button, doesn't sign in");
  assert.equal(r.headers.get("set-cookie"), null);
  assert.equal(r.headers.get("referrer-policy"), "same-origin");

  r = await post("/login/verify", { t: token });
  const cookie = r.headers.get("set-cookie");
  assert.match(cookie, /^__Host-sentinel=.+HttpOnly; Secure; SameSite=Strict/);
  r = await post("/login/verify", { t: token });
  assert.equal(r.headers.get("location"), "/login?m=expired", "link works only once");

  const sid = cookie.split(";")[0];
  r = await go("/", { headers: { Cookie: sid } });
  assert.equal(r.status, 200);
  const html = await r.text();
  assert.match(html, /Prudence Wallet/);
  assert.match(html, /DNS changed: A prudencewallet.com/);
  assert.match(html, /198\.51\.100\.x/); // masked network shown, never the full address
  assert.doesNotMatch(html, /<script/i);
  if (process.env.DUMP_HTML) (await import("node:fs")).writeFileSync(process.env.DUMP_HTML, html);

  r = await post("/ack", { id: "all" }, { Cookie: sid });
  assert.equal(r.headers.get("location"), "/?m=acked");
  const open = await (await db()).prepare("SELECT COUNT(*) AS n FROM alerts WHERE acknowledged_at IS NULL").first();
  assert.equal(open.n, 0);

  r = await post("/ack", { id: "all" }, { Cookie: sid, Origin: "https://evil.example" });
  assert.equal(r.status, 403, "CSRF blocked even with a valid session");

  r = await post("/logout", {}, { Cookie: sid });
  r = await go("/", { headers: { Cookie: sid } });
  assert.equal(r.status, 303, "session gone after sign-out");
});

test("daily report", async () => {
  await tick("2026-10-06T06:00:00Z");
  const report = lastEmail();
  assert.match(report.subject, /Daily report/);
  assert.match(report.text, /PRUDENCE WALLET/);
  assert.match(report.text, /Certificate www.prudencewallet.com: \d+ days left/);
  assert.match(report.text, /HARDENING TO DO/);
  assert.match(report.text, /prudence-wallet: 1 high/);
});
