# Sentinel

A security and uptime monitor for my web projects (Prudence Wallet, Listithub, Touch2finish), running on Cloudflare Workers' free plan.

It does two jobs:

**1. Watches each site from the outside.** It needs no changes to the sites.

| Check | How often | Catches |
|---|---|---|
| Uptime, response time, expected content | every 5 min | Outages, slow responses, defaced or wrong pages, redirects to another site |
| Security headers (HSTS, CSP, X-Content-Type-Options, framing, Referrer-Policy, Permissions-Policy) | every 5 min | Missing protections, and protections lost after a deploy |
| DNS records (A, NS, MX, TXT/SPF, CAA, DKIM, DMARC, CNAMEs) | hourly | Unexpected DNS changes, a sign of domain or email hijack |
| Certificate Transparency logs | daily | Certificates about to expire; certificates issued by an unfamiliar CA (possible mis-issuance) |
| Domain registration (RDAP) | daily | Domain about to expire; registrar transfer lock removed |

**2. Collects security events from the apps (a mini SIEM).** Apps POST their events (failed sign-ins, lockouts, errors) to Sentinel. Detection rules then look across all projects:

- any event an app marks `high`;
- a burst of failed sign-ins on one app (30 in 15 minutes);
- **the same network failing sign-ins on two or more projects within an hour**, which suggests a targeted attack rather than random bots;
- a burst of errors (10 in 15 minutes).

Alerts arrive by email through Resend. The same alert is emailed at most once an hour, and at most 40 a day. A daily report goes out at about 7am UK time.

There is also a dashboard showing every site's status, open alerts (with acknowledge buttons), recent events and the history of DNS changes.

## Security design

- **Dashboard sign-in has no password.** You enter the admin email and receive a one-time link (valid 15 minutes, single use). The link only shows a button, and signing in needs a POST, so email scanners that open links automatically can't use it up. Responses are the same whatever email is entered, so the admin address can't be discovered. Link requests are rate limited.
- **Sessions** use a random id stored only as a SHA-256 hash, in a `__Host-` cookie that is HttpOnly, Secure and SameSite=Strict, lasting 12 hours. Signing out deletes the session on the server.
- **CSRF:** every form POST must come from the same origin, on top of SameSite=Strict.
- **No JavaScript** on any page, which allows a strict CSP (`default-src 'none'`). All output is HTML-escaped.
- Sentinel sends its own security headers: HSTS, CSP, nosniff, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` (sign-in links carry a token) and Permissions-Policy.
- **Ingest** uses a separate token per app, compared in constant time, so one token can be revoked without affecting the others. Wrong tokens are rate limited and logged.
- **Data minimisation:** emails are masked (`ye***@duck.com`) and IPs cut to their network (`81.2.69.x`) on arrival. Event data is kept for 90 days and check results for 30.
- **Self-monitoring:** Sentinel's own sign-ins and rejected calls are logged as events from source `sentinel`.
- **Independence:** Sentinel runs on Cloudflare, separately from the apps (Render and Hostinger). An external monitor (UptimeRobot) watches Sentinel's `/health`, because nothing can report its own outage.
- **False-alarm guard:** if every site fails at the same moment, Sentinel sends a single "can't reach anything" alert instead of a down alert per site, because the problem is probably on Sentinel's side.

## Setup (Windows PowerShell)

You need a Cloudflare account (free) with two-factor authentication turned on, Node.js, and a Resend API key with Sending access.

```powershell
cd C:\Users\yemce\workspace\sentinel
npm install
npx wrangler login                       # opens the browser to approve
npx wrangler d1 create sentinel          # creates the database
```

If `d1 create` asks whether to add the database to your config, answer **yes**. Otherwise, copy the `database_id` it prints into `wrangler.toml`, replacing `REPLACE_WITH_DATABASE_ID`.

```powershell
npm run db:migrate                       # creates the tables
npx wrangler secret put ADMIN_EMAIL      # type your email
npx wrangler secret put RESEND_API_KEY   # paste the Resend key
npx wrangler secret put INGEST_TOKENS    # paste: prudence-wallet:<token>
npm run deploy
```

The secret prompts hide what you type or paste, so secrets never appear on screen.

To generate an ingest token, run this command; it copies the token straight to the clipboard:

```powershell
cls; $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b).Replace('+','-').Replace('/','_').TrimEnd('=') | Set-Clipboard
```

Tokens must be at least 32 characters. To add more apps, use one comma-separated line:
`prudence-wallet:<token1>,listithub:<token2>,touch2finish:<token3>`

## Adding a site

Add an entry to `SITES` in `src/config.js`, then run `npm run deploy`.

## Sending events from an app

```
POST https://<your-sentinel>.workers.dev/api/ingest
Authorization: Bearer <that app's token>
Content-Type: application/json

{ "type": "login_failed", "severity": "low", "message": "wrong password", "actor": "user@example.com", "ip": "81.2.69.142" }
```

To send several at once, use `{ "events": [ ... ] }` (up to 50 per request).

Field rules:
- `type`: lowercase letters, digits and `_ . -`.
- `severity`: one of `info`, `low`, `medium`, `high`. Only `high` and rule hits are emailed.
- `actor` and `ip` are optional, and are masked on arrival either way.

PHP, for example a WordPress or Hostinger site:

```php
function sentinel_event($type, $severity = 'info', $message = null) {
  wp_remote_post('https://<your-sentinel>.workers.dev/api/ingest', [
    'headers'  => ['Authorization' => 'Bearer ' . SENTINEL_TOKEN, 'Content-Type' => 'application/json'],
    'body'     => wp_json_encode(['type' => $type, 'severity' => $severity, 'message' => $message, 'ip' => $_SERVER['REMOTE_ADDR'] ?? null]),
    'timeout'  => 5,
    'blocking' => false,
  ]);
}
// e.g. add_action('wp_login_failed', fn($user) => sentinel_event('login_failed', 'low', 'WordPress sign-in failed'));
```

Node.js: see `backend/services/sentinel.js` in Prudence Wallet.

## Development

```powershell
copy .dev.vars.example .dev.vars
npm run db:migrate:local
npm run dev        # http://localhost:8787 — emails are printed to the console
npm test           # unit tests + end-to-end tests with every outside service mocked
```
