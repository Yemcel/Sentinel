import { test } from "node:test";
import assert from "node:assert/strict";
import { gradeHeaders, redirectedOffsite } from "../src/checks/uptime.js";
import { normaliseAnswer, fqdn } from "../src/checks/dns.js";
import { covers, siteHosts, issuerName } from "../src/checks/certs.js";
import { parseRdap, rdapUrl } from "../src/checks/domain.js";
import { cleanEvent, parseTokens } from "../src/ingest.js";
import { maskEmail, maskIp, safeEqual } from "../src/util.js";
import { plan } from "../src/scheduler.js";
import { SITES } from "../src/config.js";

test("header grading", () => {
  const none = gradeHeaders(new Headers());
  assert.equal(none.grade, "F");
  const all = gradeHeaders(
    new Headers({
      "strict-transport-security": "max-age=1",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "permissions-policy": "camera=()",
    })
  );
  assert.equal(all.grade, "A"); // frame-ancestors satisfies the framing check
  assert.deepEqual(gradeHeaders(new Headers({ "x-frame-options": "DENY" })).present, ["framing"]);
});

test("offsite redirect detection", () => {
  assert.equal(redirectedOffsite("https://prudencewallet.com/", "https://www.prudencewallet.com/", "prudencewallet.com"), false);
  assert.equal(redirectedOffsite("https://www.listithub.com/", "https://evil.example/", "listithub.com"), true);
  assert.equal(redirectedOffsite("https://x.onrender.com/api", "https://x.onrender.com/api", "prudencewallet.com"), false);
});

test("DNS normalisation", () => {
  assert.equal(fqdn("@", "a.com"), "a.com");
  assert.equal(fqdn("www", "a.com"), "www.a.com");
  const json = { Status: 0, Answer: [{ type: 5, data: "x.onrender.com." }, { type: 1, data: "1.2.3.4" }, { type: 1, data: "1.1.1.1" }] };
  assert.equal(normaliseAnswer(json, "A"), "1.1.1.1 | 1.2.3.4");
  assert.equal(normaliseAnswer(json, "CNAME"), "x.onrender.com");
  assert.equal(normaliseAnswer({ Status: 0, Answer: [{ type: 16, data: '"v=spf1 include:a" " ~all"' }] }, "TXT"), "v=spf1 include:a ~all");
  assert.equal(normaliseAnswer({ Status: 3 }, "A"), "(none)");
  assert.equal(normaliseAnswer({ Status: 0 }, "MX"), "(none)");
  assert.throws(() => normaliseAnswer({ Status: 2 }, "A"));
});

test("certificate name matching", () => {
  assert.ok(covers("www.a.com", "www.a.com"));
  assert.ok(covers("www.a.com", "*.a.com"));
  assert.ok(!covers("a.com", "*.a.com"));
  assert.ok(!covers("x.www.a.com", "*.a.com"));
  assert.deepEqual(siteHosts(SITES[0]), ["www.prudencewallet.com"]);
  assert.equal(issuerName({ issuer: { friendly_name: "Let's Encrypt" } }), "Let's Encrypt");
});

test("RDAP server choice", () => {
  assert.equal(rdapUrl("prudencewallet.com"), "https://rdap.verisign.com/com/v1/domain/prudencewallet.com");
  assert.equal(rdapUrl("touch2finish.co.uk"), "https://rdap.nominet.uk/uk/domain/touch2finish.co.uk");
  assert.equal(rdapUrl("example.ng"), "https://rdap.org/domain/example.ng");
});

test("RDAP parsing", () => {
  const info = parseRdap({
    events: [{ eventAction: "expiration", eventDate: "2027-01-01T00:00:00Z" }, { eventAction: "registration", eventDate: "2025-01-01T00:00:00Z" }],
    status: ["client transfer prohibited", "active"],
    entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Hostinger operations, UAB"]]] }],
    nameservers: [{ ldhName: "NS2.DNS-PARKING.COM" }, { ldhName: "ns1.dns-parking.com" }],
  });
  assert.equal(info.expires, "2027-01-01T00:00:00Z");
  assert.equal(info.transferLocked, true);
  assert.equal(info.registrar, "Hostinger operations, UAB");
  assert.deepEqual(info.nameservers, ["ns1.dns-parking.com", "ns2.dns-parking.com"]);
});

test("ingest cleaning and masking", () => {
  assert.equal(cleanEvent({ type: "Bad Type!" }), null);
  const ev = cleanEvent({ type: "login_failed", severity: "nope", actor: "yemcel@duck.com", ip: "81.2.69.142", at: "1999-01-01" });
  assert.equal(ev.severity, "info");
  assert.equal(ev.actor, "ye***@duck.com");
  assert.equal(ev.ip, "81.2.69.x");
  assert.notEqual(ev.at, "1999-01-01T00:00:00Z"); // far-off timestamps replaced with now
  assert.equal(maskIp("2a00:23c7:1234:5678::1"), "2a00:23c7:1234::x");
  assert.equal(maskIp("81.2.x.x"), "81.2.x.x");
  assert.equal(maskEmail("user_42"), "user_42");
  assert.deepEqual(parseTokens("a:short, b:" + "x".repeat(32)).map((t) => t.source), ["b"]);
  assert.ok(safeEqual("abc", "abc"));
  assert.ok(!safeEqual("abc", "abd"));
  assert.ok(!safeEqual("abc", "abcd"));
});

test("scheduler spreads work", () => {
  const at = (h, m) => new Date(Date.UTC(2026, 9, 4, h, m));
  assert.deepEqual(plan(at(12, 0)).map((t) => t.kind), ["uptime"]);
  assert.deepEqual(plan(at(12, 5)).map((t) => `${t.kind}:${t.site?.id || ""}`), ["uptime:", "dns:prudence"]);
  assert.deepEqual(plan(at(12, 15)).map((t) => `${t.kind}:${t.site?.id || ""}`), ["uptime:", "dns:touch2finish"]);
  assert.deepEqual(plan(at(5, 0)).map((t) => `${t.kind}:${t.site?.id || ""}`), ["uptime:", "certs:prudence"]);
  assert.deepEqual(plan(at(5, 25)).map((t) => `${t.kind}:${t.site?.id || ""}`), ["uptime:", "domain:touch2finish"]);
  assert.deepEqual(plan(at(6, 0)).map((t) => t.kind), ["uptime", "report", "prune"]);
  // every daily task gets a slot
  const daily = Array.from({ length: 12 }, (_, i) => plan(at(5, i * 5))).flat().filter((t) => t.kind === "certs" || t.kind === "domain");
  assert.equal(daily.length, SITES.length * 2);
});
