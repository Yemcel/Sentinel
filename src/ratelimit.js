import { isoMinutesAgo, nowIso } from "./util.js";

// Fixed-window rate limit. Returns true if this hit is allowed.
export async function hit(env, key, limit, windowMinutes) {
  const row = await env.DB.prepare("SELECT window_start, count FROM rate_limits WHERE key = ?").bind(key).first();
  const fresh = !row || row.window_start < isoMinutesAgo(windowMinutes);
  const count = fresh ? 1 : Number(row.count) + 1;
  await env.DB.prepare(
    "INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = excluded.count"
  )
    .bind(key, fresh ? nowIso() : row.window_start, count)
    .run();
  return count <= limit;
}
