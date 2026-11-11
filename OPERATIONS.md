# Operations

The Situation Monitor runs on GitHub Actions and GitHub Pages at https://thesituationmonitor.org/
(custom domain, Actions-based Pages deploy). The public board needs nobody: sweeps, deploys, health
checks, self-repair and the keepalive all run on schedules. This file covers every automated job,
how each fails safely, what to watch, and the keys a human can turn later.

## Automated jobs

| Workflow | When | What it does | How it fails safely |
|---|---|---|---|
| **Situation Monitor sweep** (`situation-monitor.yml`) | Every 30 minutes (at :13 and :43), on pushes of the code, prompt, sources or `sitrep.json`, and on demand | `monitor.py` sweeps the 25 sources, scores and groups reports, writes `site/data/` and the page, and sends alerts to any configured channel. Then the **pre-deploy gate** (`ops/check_build.py`) runs, the site deploys to Pages, and IndexNow is pinged (on pushes, otherwise at most once every 20 hours) | A source that fails keeps its last items on the board and shows as failing in the Sources table. The gate stops the run before deploying if the page, data (including `more.json`, the part of the board the page loads on demand), feed, prompt, sitemap or IndexNow key is broken, if the data isn't from this sweep, or if fewer than 60% of sources answered; the last good deploy stays live. It only warns when the page lacks its pre-rendered reports or the first load (page plus `situation.json`) passes 150 KB compressed. The IndexNow ping never fails the run. |
| **Sweep → archive job** (same workflow) | After each deployed sweep | `ops/archive.py save` commits any new SITREP, the snapshot of each finished UTC day and (daily) the sweep's memory to the orphan `data` branch. It is the only job with `contents: write`; the sweep job hands it the memory as a one-day artifact | Writes only what is missing, so most runs commit nothing. If it fails, the deploy has already happened; the next run fills in whatever was missed, because each day is written from the 14-day memory. |
| **Health** (`health.yml`) | Hourly at :27 | `ops/health.py --heal` reads the live board: page (and the reports written into it), data freshness, `more.json` matching `situation.json`, first-load size, sources answering, item count, SITREP age, RSS feed, master prompt, robots.txt, sitemap, IndexNow key, TLS certificate life. **When the live data is over 75 minutes old and no sweep is queued, it dispatches a sweep itself.** | Read-only towards the site. Fails loudly (`::error::`) when the data is over 6 hours old, a file is broken, fewer than 60% of sources answer, or the certificate has under 10 days left. Warns at 2 hours, on any failing source, on a missing SITREP, under 21 days of certificate, on fewer than 20 reports in the page's HTML, on a first load over 150 KB and on a `more.json` from another sweep (a deploy landing mid-check). |
| **Checks** (`checks.yml`) | Every push and pull request; Sundays 08:37 UTC | Unit tests (feed parsing, scoring, rendering, the gate), including severity precision and recall against the hand-labelled headlines, shown in the run summary. On Sundays it is the **weekly self-test**: the tests plus a read-only health check of the live board | Changes nothing. A red run means a code change broke something or the board is unhealthy. |
| **Checks → keepalive** | Sundays, same workflow | Commits `.github/keepalive` after 30 days without a commit and re-enables any workflow GitHub disabled for inactivity | GitHub disables scheduled workflows in a public repo after 60 days without a commit. The analyst's SITREP commits normally keep the repo active; the heartbeat covers the weeks they stop. |
| **Analyst SITREP** (not in Actions) | Hourly, while the owner's Claude app is open | A Claude scheduled task on the owner's Mac starts a sweep here, waits for it to deploy, reads the published data (`monitor.py --from-site`; it never sweeps itself), writes the briefing and commits `sitrep.json`, which triggers another sweep and deploy. If its push is rejected because `main` moved, it pulls with rebase and retries | Optional. The site drops a SITREP older than 36 hours, so stale analysis never lingers, and the board works without one. |

### Why the sweep has a second trigger

GitHub delays and drops scheduled runs at busy minutes. The original `*/30` schedule (minutes :00 and
:30) ran only about every 3–4 hours. The sweep now runs at :13 and :43, and the hourly health check
starts a sweep whenever the live data is over 75 minutes old. Two independent schedules have to miss
before the board goes stale.

## What to watch

- **Actions tab → Health.** Red means the board is stale or broken; the run summary lists every check
  and the failing sources. Sustained red with "data freshness" failing means sweeps aren't completing:
  open the latest **Situation Monitor sweep** run and read the gate's annotations.
- **CISA from GitHub:** cisa.gov answers HTTP 403 to GitHub's runners (it works from a home connection).
  *CISA Advisories* then falls back to the CSAF documents CISA publishes in its `cisagov/CSAF` repository
  (ICS and IT advisories; CISA's news items and joint guidance aren't there), and the Sources table says
  "Reporting via CISA's CSAF repository". *CISA KEV* falls back to `cisagov/kev-data` the same way. A
  source fails only when both routes fail.
- **Failure emails** for scheduled runs go to the account owner. Nothing else alerts.
- **Clocks.** A sweep takes real time from the `Date` headers of GitHub, Google and Cloudflare, so a wrong
  machine clock can't put timestamps in the future. `data/situation.json` and `monitor.py --summary` carry
  `clock.skew_seconds`, plus a `warning` when the machine is off by more than 2 minutes; fix that machine's clock.
  A briefing stamped later than its sweep is shown with the sweep's time. The page takes "now" from the data
  response's `Date` header, so a visitor with a wrong clock still sees the right "swept … ago" and Live badge.
- **State lives in the Actions cache** (`state/`, key `situation-state-<run id>`). GitHub evicts caches
  unused for 7 days. If that happens, the sweep restores the copy the archive job keeps on the `data`
  branch (at most a day old), so only reports from that last day can be flagged as new again. Only if the
  branch is missing too does it start a fresh baseline that alerts on nothing on its first run.
- **First load.** The page and `data/situation.json` should stay under 150 KB compressed (about 100 KB in
  Nov 2026). `monitor.py` keeps fewer critical and high reports in `situation.json` when they would pass that
  (`BOARD_PRIORITY`), and the gate and the health check warn if it is passed anyway. Everything else is in
  `data/more.json`, which must come from the same sweep; the page and `--from-site` retry when a deploy
  lands between the two downloads.
- **The `data` branch is the permanent record.** Never merge it into `main`, and don't rewrite its
  history: later pages (daily briefings, situation pages) will be built from it.

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
4. **Google Search Console** is done: the domain property was verified through a DNS TXT record
   (`google-site-verification=…` on `thesituationmonitor.org`, set at Namecheap) on Oct 24, 2026, and
   `https://thesituationmonitor.org/sitemap.xml` is submitted. Keep that TXT record. Bing, Yandex and others
   get IndexNow pings. (`config.json` can also carry `"google_site_verification"` for the HTML-tag method;
   it isn't needed.)
5. **Other domains.** `cyops.fun` is meant to redirect here. That's a DNS change for the owner; the Pages
   custom-domain setting here must not change.

## Scheduled Claude routine

The analyst routine already exists: *The Situation Monitor: hourly sweep*, a Claude scheduled task on the
owner's Mac that fast-forwards its checkout to `main`, starts the GitHub sweep, and runs
`monitor.py --from-site --wait 150`. That waits for the sweep to deploy and reads what the site published;
the Mac sweeps nothing and keeps no board of its own (only `state/analyst.json`: the newest first-seen
time and level it has reported). It rewrites the SITREP from the published board when something new is
critical or high, the level changes or the SITREP is over 6 hours old, commits `sitrep.json`, syncs the
private claude.ai live copy from the published `live.json` (`--apply-sitrep` adds the new SITREP), and
sends the owner a push notification for new critical or watchlisted items. If GitHub's memory is reset
(an evicted cache), the analyst treats the next look as a baseline instead of alerting on everything. If
it is ever moved to a cloud routine, keep its one rule: it commits only `sitrep.json`.
