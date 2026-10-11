// What Sentinel watches. Add a site by adding an entry here and redeploying.
//
// targets  — URLs checked every 5 minutes.
//   expect: text that must appear in the response (catches a defaced or
//           wrong page that still returns 200). null = status code only.
//   html:   true for web pages — their security headers are graded.
// dns      — [name, type] records snapshotted hourly; any change is alerted.
//            "@" is the bare domain.
// The DNS list includes the email records (MX, SPF, DKIM, DMARC): a change
// there can mean someone is redirecting or spoofing the domain's email.

export const SITES = [
  {
    id: "prudence",
    name: "Prudence Wallet",
    domain: "prudencewallet.com",
    targets: [
      { id: "prudence-web", label: "Website", url: "https://www.prudencewallet.com/", expect: "prudence", html: true },
      { id: "prudence-api", label: "Backend", url: "https://prudence-wallet.onrender.com/api/health", expect: '"ok":true', html: false },
    ],
    dns: [
      ["@", "A"], ["@", "NS"], ["@", "MX"], ["@", "TXT"], ["@", "CAA"],
      ["www", "CNAME"], ["_dmarc", "TXT"], ["resend._domainkey", "TXT"], ["send", "CNAME"], ["rsend", "CNAME"],
    ],
  },
  {
    id: "listithub",
    name: "Listithub",
    domain: "listithub.com",
    targets: [{ id: "listithub-web", label: "Website", url: "https://www.listithub.com/", expect: null, html: true }],
    dns: [["@", "A"], ["@", "NS"], ["@", "MX"], ["@", "TXT"], ["@", "CAA"], ["www", "CNAME"], ["_dmarc", "TXT"]],
  },
  {
    id: "touch2finish",
    name: "Touch2finish",
    domain: "touch2finish.co.uk",
    targets: [{ id: "touch2finish-web", label: "Website", url: "https://touch2finish.co.uk/", expect: null, html: true }],
    dns: [["@", "A"], ["@", "NS"], ["@", "MX"], ["@", "TXT"], ["@", "CAA"], ["www", "CNAME"], ["_dmarc", "TXT"]],
  },
];

// Thresholds
export const DOWN_AFTER_FAILURES = 2; // 2 failed checks in a row (≈10 min) = down
export const REQUEST_TIMEOUT_MS = 45000; // Render's free backend can take ~40s to wake
export const SLOW_MS = 10000;
export const CERT_WARN_DAYS = 14; // certificates normally renew ~30 days before expiry
export const DOMAIN_WARN_DAYS = [30, 14, 7, 1];
export const ALERT_DEDUPE_MINUTES = 60;
export const DAILY_EMAIL_CAP = 40;
export const RETENTION = { checksDays: 30, eventsDays: 90, alertsDays: 180 };

// Detection rules for app events
export const RULES = {
  failedLoginSpike: { count: 30, minutes: 15 }, // per source
  errorSpike: { count: 10, minutes: 15 }, // per source
  crossProject: { sources: 2, minutes: 60 }, // same address failing on 2+ projects
};

export function allTargets() {
  return SITES.flatMap((site) => site.targets.map((t) => ({ ...t, site })));
}

export function siteById(id) {
  return SITES.find((s) => s.id === id);
}
