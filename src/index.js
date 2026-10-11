import { siteById } from "./config.js";
import { CSS } from "./css.js";
import { overview, overallStatus } from "./data.js";
import { handleIngest } from "./ingest.js";
import { currentSession, redeemLink, requestLink, sameOrigin, signOut } from "./auth.js";
import { dashboardPage, loginPage, verifyPage } from "./views.js";
import { runScheduled } from "./scheduler.js";
import { checkTarget } from "./checks/uptime.js";
import { checkDns } from "./checks/dns.js";
import { checkCerts } from "./checks/certs.js";
import { checkDomain } from "./checks/domain.js";
import { setFact } from "./facts.js";
import { nowIso } from "./util.js";

// Sentinel's own response headers: it practises what it checks for.
const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  // Sign-in links carry a token in the URL: never send it to other sites.
  // (Not "no-referrer", which makes browsers send "Origin: null" on form posts.)
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Cross-Origin-Opener-Policy": "same-origin",
};

// Fixed messages only — nothing from the URL is echoed back to the page.
const FLASH = {
  sent: "If that's the admin email, a sign-in link is on its way. It expires in 15 minutes.",
  limited: "Too many attempts. Please wait an hour and try again.",
  expired: "That link is invalid, expired or already used. Request a new one.",
  "signed-out": "Signed out.",
  running: "Checks started. Refresh in a minute to see the results.",
  acked: "Acknowledged.",
};

function respond(body, { status = 200, type = "text/html; charset=utf-8", headers = {} } = {}) {
  return new Response(body, { status, headers: { "Content-Type": type, "Cache-Control": "no-store", ...SECURITY_HEADERS, ...headers } });
}
const redirect = (to, headers = {}) => new Response(null, { status: 303, headers: { Location: to, "Cache-Control": "no-store", ...SECURITY_HEADERS, ...headers } });

async function form(request) {
  try {
    return await request.formData();
  } catch {
    return new FormData();
  }
}

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const { pathname } = url;
  const method = request.method;
  const flash = FLASH[url.searchParams.get("m")] || "";

  if (pathname === "/app.css") return respond(CSS, { type: "text/css; charset=utf-8", headers: { "Cache-Control": "public, max-age=3600" } });
  if (pathname === "/health") return respond(JSON.stringify({ ok: true, at: nowIso() }), { type: "application/json" });
  if (pathname === "/robots.txt") return respond("User-agent: *\nDisallow: /\n", { type: "text/plain" });
  if (pathname === "/api/ingest" && method === "POST") return handleIngest(request, env, ctx);

  // --- Sign-in --------------------------------------------------------------------
  if (pathname === "/login" && method === "GET") return respond(loginPage(flash));
  if (pathname === "/login" && method === "POST") {
    if (!sameOrigin(request)) return respond("Forbidden", { status: 403, type: "text/plain" });
    const result = await requestLink(request, env, (await form(request)).get("email"));
    return redirect(`/login?m=${result.limited ? "limited" : "sent"}`);
  }
  if (pathname === "/login/verify" && method === "GET") {
    const token = url.searchParams.get("t") || "";
    if (!/^[A-Za-z0-9_-]{20,100}$/.test(token)) return redirect("/login?m=expired");
    return respond(verifyPage(token));
  }
  if (pathname === "/login/verify" && method === "POST") {
    if (!sameOrigin(request)) return respond("Forbidden", { status: 403, type: "text/plain" });
    const cookie = await redeemLink(request, env, (await form(request)).get("t"));
    return cookie ? redirect("/", { "Set-Cookie": cookie }) : redirect("/login?m=expired");
  }

  // --- Everything below needs a session ----------------------------------------------
  const session = await currentSession(request, env);
  if (!session) return method === "GET" ? redirect("/login") : respond("Unauthorized", { status: 401, type: "text/plain" });
  if (method === "POST" && !sameOrigin(request)) return respond("Forbidden", { status: 403, type: "text/plain" });

  if (pathname === "/logout" && method === "POST") return redirect("/login?m=signed-out", { "Set-Cookie": await signOut(request, env) });

  if (pathname === "/" && method === "GET") {
    ctx.waitUntil(setFact(env, "sentinel", "dashboard_url", url.origin));
    const [o, alerts, events, dnsChanges] = await Promise.all([
      overview(env),
      // Repeats of the same alert (same key) are shown once, with a count.
      env.DB.prepare(
        `SELECT a.id, a.key, a.severity, a.title, a.body, a.created_at, g.n FROM alerts a
         JOIN (SELECT key, MAX(id) AS id, COUNT(*) AS n FROM alerts WHERE acknowledged_at IS NULL AND severity IN ('medium','high') GROUP BY key) g ON g.id = a.id
         ORDER BY a.id DESC LIMIT 50`
      ).all().then((r) => r.results),
      env.DB.prepare("SELECT source, type, severity, message, actor, ip, at FROM events ORDER BY id DESC LIMIT 30").all().then((r) => r.results),
      env.DB.prepare("SELECT site_id, name, type, old_value, new_value, at FROM dns_changes ORDER BY id DESC LIMIT 20").all().then((r) => r.results),
    ]);
    return respond(dashboardPage({ o, status: overallStatus(o), alerts, events, dnsChanges, flash }));
  }

  if (pathname === "/ack" && method === "POST") {
    const id = (await form(request)).get("id");
    if (id === "all") await env.DB.prepare("UPDATE alerts SET acknowledged_at = ? WHERE acknowledged_at IS NULL").bind(nowIso()).run();
    // Acknowledging an alert also acknowledges its earlier repeats.
    else if (/^\d+$/.test(String(id))) await env.DB.prepare("UPDATE alerts SET acknowledged_at = ?1 WHERE acknowledged_at IS NULL AND key = (SELECT key FROM alerts WHERE id = ?2)").bind(nowIso(), Number(id)).run();
    return redirect("/?m=acked");
  }

  if (pathname === "/run" && method === "POST") {
    const site = siteById(String((await form(request)).get("site")));
    if (!site) return redirect("/");
    ctx.waitUntil(
      (async () => {
        for (const job of [
          () => Promise.all(site.targets.map((tg) => checkTarget(env, { ...tg, site }))),
          () => checkDns(env, site),
          () => checkCerts(env, site),
          () => checkDomain(env, site),
        ]) {
          try {
            await job();
          } catch (err) {
            console.error(`Manual check for ${site.id} failed:`, err.message);
          }
        }
      })()
    );
    return redirect("/?m=running");
  }

  return respond("Not found", { status: 404, type: "text/plain" });
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (err) {
      console.error("Request failed:", err.stack || err.message);
      return respond("Something went wrong", { status: 500, type: "text/plain" });
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduled(env, new Date(event.scheduledTime)));
  },
};
