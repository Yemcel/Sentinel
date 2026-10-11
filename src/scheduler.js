import { SITES, RETENTION, allTargets } from "./config.js";
import { checkAllTargets } from "./checks/uptime.js";
import { checkDns } from "./checks/dns.js";
import { checkCerts } from "./checks/certs.js";
import { checkDomain } from "./checks/domain.js";
import { sendDailyReport } from "./report.js";
import { isoMinutesAgo } from "./util.js";

// Runs every 5 minutes. Uptime is checked on every tick; the heavier checks
// are spread out so each run stays well inside the free plan's limits:
//   - DNS: one site per tick at the start of each hour
//   - certificates and domains: one site per tick, once a day (05:xx UTC)
//   - daily report and clean-up: 06:00 UTC
export function plan(date) {
  const hour = date.getUTCHours();
  const slot = Math.floor(date.getUTCMinutes() / 5); // 0..11
  const tasks = [{ kind: "uptime" }];

  if (slot >= 1 && slot <= SITES.length) tasks.push({ kind: "dns", site: SITES[slot - 1] });

  if (hour === 5) {
    const daily = SITES.flatMap((site) => [{ kind: "certs", site }, { kind: "domain", site }]);
    if (daily[slot]) tasks.push(daily[slot]);
  }
  if (hour === 6 && slot === 0) tasks.push({ kind: "report" }, { kind: "prune" });
  return tasks;
}

export async function runTask(env, task) {
  switch (task.kind) {
    case "uptime":
      return checkAllTargets(env, allTargets());
    case "dns":
      return checkDns(env, task.site);
    case "certs":
      return checkCerts(env, task.site);
    case "domain":
      return checkDomain(env, task.site);
    case "report":
      return sendDailyReport(env);
    case "prune":
      return prune(env);
    default:
      throw new Error(`Unknown task ${task.kind}`);
  }
}

export async function runScheduled(env, date) {
  const results = [];
  for (const task of plan(date)) {
    try {
      results.push({ task: task.kind, site: task.site?.id, result: await runTask(env, task) });
    } catch (err) {
      console.error(`Task ${task.kind} ${task.site?.id || ""} failed:`, err.message);
      results.push({ task: task.kind, site: task.site?.id, error: err.message });
    }
  }
  return results;
}

async function prune(env) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM checks WHERE at < ?").bind(isoMinutesAgo(RETENTION.checksDays * 1440)),
    env.DB.prepare("DELETE FROM events WHERE at < ?").bind(isoMinutesAgo(RETENTION.eventsDays * 1440)),
    env.DB.prepare("DELETE FROM alerts WHERE created_at < ?").bind(isoMinutesAgo(RETENTION.alertsDays * 1440)),
    env.DB.prepare("DELETE FROM certificates WHERE not_after < ?").bind(isoMinutesAgo(30 * 1440)),
    env.DB.prepare("DELETE FROM login_tokens WHERE expires_at < ?").bind(isoMinutesAgo(60)),
    env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(isoMinutesAgo(0)),
    env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(isoMinutesAgo(1440)),
  ]);
  return { pruned: true };
}
