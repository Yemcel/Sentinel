// Small shared helpers. No dependencies — Workers provide Web Crypto.

export const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
export const isoMinutesAgo = (m) => new Date(Date.now() - m * 60000).toISOString().replace(/\.\d{3}Z$/, "Z");
export const isoMinutesAhead = (m) => new Date(Date.now() + m * 60000).toISOString().replace(/\.\d{3}Z$/, "Z");
export const daysUntil = (iso) => (iso ? Math.floor((Date.parse(iso) - Date.now()) / 86400000) : null);

export async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomToken(bytes = 32) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Constant-time comparison, so a token can't be guessed character by
// character from response timings.
export function safeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

// Personal data is masked before it is stored: Sentinel only needs enough
// to spot patterns (the same network attacking several projects), not
// exact identities. Full details stay in each app's own logs.
export function maskIp(ip) {
  const s = String(ip ?? "").trim();
  if (!s) return null;
  const v4 = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.x`;
  if (s.includes(":")) return s.split(":").slice(0, 3).join(":") + "::x"; // IPv6 /48
  if (/\.x$|::x$/.test(s)) return s.slice(0, 64); // already masked by the sender
  return null;
}

export function maskEmail(email) {
  const s = String(email ?? "").trim();
  const m = s.match(/^([^@\s]{1,2})[^@\s]*@([^@\s]+)$/);
  if (m) return `${m[1]}***@${m[2]}`.slice(0, 120);
  return s ? s.slice(0, 120) : null; // not an email (e.g. a user id) — keep as is
}

export function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

export function clientIp(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

// fetch with a timeout. Waiting on the network doesn't count towards the
// Worker's CPU limit, only actual processing does.
export async function fetchWithTimeout(url, init = {}, ms = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("timeout"), ms);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
