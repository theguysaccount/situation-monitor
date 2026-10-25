# Operations

The Situation Monitor runs on GitHub Actions and GitHub Pages at https://thesituationmonitor.org/
(custom domain, Actions-based Pages deploy). The public board needs nobody: sweeps, deploys, health
checks, self-repair and the keepalive all run on schedules. This file covers every automated job,
how each fails safely, what to watch, and the keys a human can turn later.

## Automated jobs

| Workflow | When | What it does | How it fails safely |
|---|---|---|---|
| **Situation Monitor sweep** (`situation-monitor.yml`) | Every 30 minutes (at :13 and :43), on pushes of the code, prompt, sources or `sitrep.json`, and on demand | `monitor.py` sweeps the 25 sources, scores and groups reports, writes `site/data/` and the page, and sends alerts to any configured channel. Then the **pre-deploy gate** (`ops/check_build.py`) runs, the site deploys to Pages, and IndexNow is pinged (on pushes, otherwise at most once every 20 hours) | A source that fails keeps its last items on the board and shows as failing in the Sources table. The gate stops the run before deploying if the page, data, feed, prompt, sitemap or IndexNow key is broken, if the data isn't from this sweep, or if fewer than 60% of sources answered; the last good deploy stays live. The IndexNow ping never fails the run. |
| **Health** (`health.yml`) | Hourly at :27 | `ops/health.py --heal` reads the live board: page, data freshness, sources answering, item count, SITREP age, RSS feed, master prompt, robots.txt, sitemap, IndexNow key, TLS certificate life. **When the live data is over 75 minutes old and no sweep is queued, it dispatches a sweep itself.** | Read-only towards the site. Fails loudly (`::error::`) when the data is over 6 hours old, a file is broken, fewer than 60% of sources answer, or the certificate has under 10 days left. Warns at 2 hours, on any failing source, on a missing SITREP and under 21 days of certificate. |
| **Checks** (`checks.yml`) | Every push and pull request; Sundays 08:37 UTC | Unit tests (feed parsing, scoring, rendering, the gate). On Sundays it is the **weekly self-test**: the tests plus a read-only health check of the live board | Changes nothing. A red run means a code change broke something or the board is unhealthy. |
| **Checks → keepalive** | Sundays, same workflow | Commits `.github/keepalive` after 30 days without a commit and re-enables any workflow GitHub disabled for inactivity | GitHub disables scheduled workflows in a public repo after 60 days without a commit. The analyst's SITREP commits normally keep the repo active; the heartbeat covers the weeks they stop. |
| **Analyst SITREP** (not in Actions) | Hourly, while the owner's Claude app is open | A Claude scheduled task on the owner's Mac writes the briefing and commits `sitrep.json`, which triggers a sweep and deploy. If its push is rejected because `main` moved, it pulls with rebase and retries | Optional. The site drops a SITREP older than 36 hours, so stale analysis never lingers, and the board works without one. |

### Why the sweep has a second trigger

GitHub delays and drops scheduled runs at busy minutes. The original `*/30` schedule (minutes :00 and
:30) ran only about every 3–4 hours. The sweep now runs at :13 and :43, and the hourly health check
starts a sweep whenever the live data is over 75 minutes old. Two independent schedules have to miss
before the board goes stale.

## What to watch

- **Actions tab → Health.** Red means the board is stale or broken; the run summary lists every check
  and the failing sources. Sustained red with "data freshness" failing means sweeps aren't completing:
  open the latest **Situation Monitor sweep** run and read the gate's annotations.
- **Known source failure:** *CISA Advisories* answers HTTP 403 to GitHub's runners (it works from a home
  connection), so it shows as failing on the public board and in Health warnings. CISA's Known Exploited
  Vulnerabilities feed is a separate source and is unaffected.
- **Failure emails** for scheduled runs go to the account owner. Nothing else alerts.
- **State lives in the Actions cache** (`state/`, key `situation-state-<run id>`). GitHub evicts caches
  unused for 7 days. If sweeps stop for over a week, the next sweep starts a fresh baseline: it alerts on
  nothing on its first run, and the history charts refill from the archives.

## Keys a human can turn later

None of these is needed for the board to keep running.

1. **Alerts.** No alert channel is configured, so sweeps publish but notify no one. To turn alerts on, add
   repository secrets under Settings → Secrets and variables → Actions: `SM_SLACK_WEBHOOK`,
   `SM_TEAMS_WEBHOOK`, `SM_DISCORD_WEBHOOK`, `SM_NTFY_TOPIC` or `SM_WEBHOOK_URL`, plus optional
   variables `SM_WATCHLIST` (comma-separated names) and `SM_MIN_SEVERITY`. The next sweep uses them.
2. **Server-side analyst.** The SITREP needs the owner's Mac. Moving it into Actions needs an Anthropic API
   key as a repository secret and a workflow step that writes `sitrep.json` in the same format as
   `state/sitrep.json`. Until then the board runs without a SITREP whenever the Mac is off.
3. **Money: paid team digests.** GitHub Pages is for non-commercial sites, so a paid tier (Stripe-billed
   digests matched to a team's uploaded lockfiles) needs separate hosting and a Stripe account. The free
   board stays here. When it exists, add one link labeled "Team digests" to the "Get alerted" section of
   `site/app.html`.
4. **Google Search Console.** Verify the domain in Search Console with the HTML-tag method, then add
   `"google_site_verification": "<token>"` to `config.json` and push; `monitor.py` adds the meta tag to the
   page. Then submit `https://thesituationmonitor.org/sitemap.xml`. Bing, Yandex and others already get
   IndexNow pings.
5. **Other domains.** `cyops.fun` is meant to redirect here. That's a DNS change for the owner; the Pages
   custom-domain setting here must not change.

## Scheduled Claude routine

The analyst routine already exists: *The Situation Monitor: hourly sweep*, a Claude scheduled task on the
owner's Mac that runs `monitor.py --summary`, rewrites the SITREP when something new is critical or high,
the level changes or the SITREP is over 6 hours old, commits `sitrep.json`, syncs the private claude.ai
live copy, and sends the owner a push notification for new critical or watchlisted items. If it is ever
moved to a cloud routine, keep its one rule: it commits only `sitrep.json`.
