-- Sentinel database (Cloudflare D1 / SQLite)

-- Current state of each monitored URL.
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'unknown',   -- up | down | unknown
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_checked TEXT,
  last_change TEXT,
  last_status_code INTEGER,
  last_latency_ms INTEGER,
  last_error TEXT,
  final_url TEXT,
  headers_json TEXT,                         -- security headers present, last check
  headers_grade TEXT
);

-- Every uptime check (kept 30 days) for uptime % and latency.
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  ok INTEGER NOT NULL,
  status_code INTEGER,
  latency_ms INTEGER,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_target_at ON checks (target_id, at);

-- Latest DNS answer per site/name/type, and a log of changes.
CREATE TABLE IF NOT EXISTS dns_snapshots (
  site_id TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  PRIMARY KEY (site_id, name, type)
);
CREATE TABLE IF NOT EXISTS dns_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  old_value TEXT,
  new_value TEXT,
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Per-site facts from the daily checks (certificates, domain registration).
CREATE TABLE IF NOT EXISTS site_facts (
  site_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (site_id, key)
);

-- Certificates seen in Certificate Transparency logs.
CREATE TABLE IF NOT EXISTS certificates (
  id TEXT PRIMARY KEY,                       -- certspotter issuance id
  site_id TEXT NOT NULL,
  dns_names TEXT NOT NULL,
  issuer TEXT,
  not_before TEXT,
  not_after TEXT,
  first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_certs_site ON certificates (site_id);

-- Security events sent in by the apps (the mini SIEM), plus Sentinel's own.
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,                    -- info | low | medium | high
  message TEXT,
  actor TEXT,                                -- masked email / user
  ip TEXT,                                   -- masked to a.b.c.x
  at TEXT NOT NULL,
  received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_events_at ON events (at);
CREATE INDEX IF NOT EXISTS idx_events_ip_at ON events (ip, at);
CREATE INDEX IF NOT EXISTS idx_events_source_type_at ON events (source, type, at);

-- Alerts raised by checks and rules.
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  site_id TEXT,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  emailed INTEGER NOT NULL DEFAULT 0,
  acknowledged_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_key_created ON alerts (key, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts (acknowledged_at, created_at);

-- Dashboard sign-in: one-time email links and sessions (only hashes stored).
CREATE TABLE IF NOT EXISTS login_tokens (
  token_hash TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  ip TEXT
);

-- Fixed-window counters for rate limits.
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  window_start TEXT NOT NULL,
  count INTEGER NOT NULL
);
