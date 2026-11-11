# The Situation Monitor

*"I am monitoring the situation."*

One page that pulls together the hacks, breaches, exploited vulnerabilities and
supply-chain attacks happening right now. It scores them, groups the stories
several outlets are covering into developing situations, and turns all of it
into a master prompt your team can paste into Claude to check its own exposure.

- **Live site:** https://thesituationmonitor.org/
- **RSS of critical and high reports:** https://thesituationmonitor.org/data/feed.xml
- **Master prompt with today's data:** https://thesituationmonitor.org/data/master-prompt.md
- **Updates:** every 30 minutes through GitHub Actions. The analyst briefing (SITREP) is written by a Claude scheduled task and committed as `sitrep.json`.

## What's here

| File | What it does |
|---|---|
| `monitor.py` | The sweep. Fetches every source, normalises and de-duplicates, scores severity, groups developing situations, works out the SITCON level, writes `site/data/`, sends alerts. Python 3.9+, standard library only. |
| `sources.json` | The source list. Add or remove feeds here. |
| `config.json` | Alert channels, watchlist, SITCON thresholds, public site URL. |
| `MASTER_PROMPT.md` | The master prompt template that the site and the sweep fill with live data. |
| `site/app.html` | The website, one file. Each sweep generates `site/index.html` from it, with the sweep's content written into the page (see [The page](#the-page)). |
| `.github/workflows/situation-monitor.yml` | Public deploy: sweep every 30 minutes and publish to GitHub Pages. |
| `sitrep.json` | The latest analyst briefing, committed by the scheduled task so the public site shows it. |
| `state/` | The monitor's memory: what it has seen and alerted on. Not committed; the workflow keeps it in the Actions cache, with a daily copy on the `data` branch. |
| `data` branch | The permanent record, never deployed: every SITREP, one snapshot per day since Oct 24, 2026, and the sweep's memory. See [The archive](#the-archive). |
| `ops/` | Unattended operation: the pre-deploy gate, the live health check that also restarts overdue sweeps, and the IndexNow ping. See [OPERATIONS.md](OPERATIONS.md). |
| `tests/` | Unit tests: `python3 -m unittest discover -s tests` |

## Run it

```bash
python3 monitor.py
```

```bash
python3 -m http.server 8765 --directory site
```

Then open http://localhost:8765. Other modes: `--summary` (JSON summary for
automation), `--brief` (the current situation as text), `--rebuild` (re-render
from the last sweep without fetching), `--no-alerts`, `--test-alert`, and the
analyst's `--from-site [--wait SECONDS]` and `--apply-sitrep` (below).

Each sweep writes:

- `site/index.html`: the page, with the level, the SITREP, the developing situations, the top 20 reports and the latest exploited CVEs already in the HTML
- `site/data/situation.json`: what the page shows on arrival: everything on the board except the reports in `more.json`, plus `more` (what was left out, and each feed tab's count over the whole board)
- `site/data/more.json`: the rest of the board: ransomware claims, low-severity and older reports, older malicious packages. The page loads it only when a view needs it
- `site/data/live.json`: the whole board, trimmed to fit the live site's 256 KB store
- `site/data/feed.xml`: RSS of critical and high-severity reports
- `site/data/master-prompt.md`: the master prompt filled with the latest data, ready to paste
- `site/data/new.json`: what is new since the previous sweep
- `site/data/changes.json`: the level and every critical or high report first seen in the last 7 days, with first-seen times (small; the analyst polls it)

## The page

The page is one file with no build step, but each sweep writes its content into the copy it publishes.
`monitor.py` fills the elements of `site/app.html` that the page script would fill (the SITCON board and
its reason, the stat tiles, the SITREP, the developing situations, the feed tabs, the 20 newest critical
and high reports, the CISA KEV panel and the CVE monitor's latest additions) and saves the result as
`site/index.html`. So the page reads without JavaScript, for search engines, link previews and slow phones.
The script then downloads the data and replaces that markup with the live, interactive version. Feed text
is escaped and only `http(s)` links are written; if rendering ever fails, the sweep publishes the plain
template and logs a warning.

The data comes in two files. `data/situation.json` holds what the page shows on arrival: the 150 newest
critical and high reports (fewer if the page and this file would pass 150 KB compressed), every KEV
addition, the newest ransomware claims and breach disclosures for the side panels, every report in a
developing situation, and the 20 newest malicious packages. `data/more.json` holds the rest, about nine
reports in ten, and the page fetches it the first time a view needs it: another feed tab, a search, "Your
stack only", a watchlist, or scrolling past the reports already loaded. A first visit transfers about
100 KB (the page and `situation.json`, compressed) instead of 355 KB. To read the whole board from a
script, download both files and join their `items` and `packages` lists (newest first), as
`monitor.py --from-site` does.

## Sources

The monitor builds on public projects that already track this, rather than scraping:

- **Exploited vulnerabilities:** CISA's Known Exploited Vulnerabilities catalog (falls back to the `cisagov/kev-data` GitHub mirror)
- **Ransomware:** ransomware.live (leak-site victims, plus press and regulator disclosures) and RansomLook
- **Breaches:** Have I Been Pwned's breach list, ransomware.live disclosures, newsroom coverage
- **Supply chain:** GitHub Advisory Database malware advisories (npm and PyPI) and critical advisories
- **Advisories:** CISA, the UK NCSC, the Microsoft Security Blog
- **News:** BleepingComputer, The Hacker News, The Record, Krebs on Security, DataBreaches.net, SecurityWeek, Dark Reading, The Register, CyberScoop, TechCrunch, Help Net Security, Cybersecurity Dive, WIRED, SANS Internet Storm Center
- **Community:** Hacker News stories about breaches and exploits (through the Algolia API); a thread about a story already on the board becomes a note on that story

A source that fails keeps its last items on the board, and the Sources table on the site shows it as failing.

## How it scores

- **Severity** answers "should a security team hear about this today?" It comes from the headline (summary-only words count half): something happened (a breach, theft, attack, ransomware, a malicious release), active exploitation, zero-days, critical flaws, worms, emergency patches, nation-state attribution, big record counts. A story only reaches **critical** when its headline names something to patch or hunt now (exploitation, a zero-day, a malicious release, a worm, a critical flaw). Headlines that are roundups, questions, advice, research, predictions, business news, courts, arrests or policy are capped at medium.
- The rules are measured against 300 hand-labelled headlines in `tests/fixtures/scoring_gold.json`: on the 30% held out, high-or-critical has precision 0.85 and recall 0.89 (November 2026). `python3 tests/test_scoring.py` prints the current numbers and the mistakes on the tuning part; the checks fail if held-out precision or recall drops below 0.85.
- **CISA KEV entries** are critical for 72 hours after they're added, or for as long as they're tied to ransomware; high after that.
- **Have I Been Pwned breaches** are critical at 10M+ accounts and high at 1M+.
- **Developing situations** are names and CVEs that at least three outlets carried in the last 72 hours (two, if one is CISA KEV), merged when they share most of their reports.
  - Roundups and headlines that list several products ("OpenSSH, GPUStack, FreeSWITCH, and IBM") join no story. Generic words (Secure, Firewall, University, SSH) and platform names (Microsoft, Claude) never link reports on their own.
  - A CISA KEV entry links only through its CVE and its product's name, and two KEV entries for different products never share a story.
  - A vendor's name links reports only when nothing more specific does ("Oracle" when the reports share no product word).
  - The name is a coined bug name when two reports use one (SSHole, PHP2Shell, ICM2SHELL), else a product or phrase the reports share; never a bare vendor or country. Failing those it's the product and CVE ("GitLab CVE-2026-97229") or the lead headline.
  - `tests/fixtures/situations.json` holds two real boards (Oct 31 and Nov 10, 2026) that the tests group and name.
- **SITCON** adds up a "heat" score and maps it through `level_thresholds` in `config.json` (250, 290, 405, 430): 5 quiet, 4 guarded, 3 elevated, 2 severe, 1 critical.
  - Heat counts reports from the last 48 *working* hours (Monday to Friday, UTC) by severity (critical 6, high 2.5, medium 0.6), 4 for each CISA KEV addition in the last 72 working hours, 0.25 for each ransomware leak-site claim in the last 48 hours (at most 20), and 5 for each story on five or more outlets. Counting working hours means a quiet weekend still sees Thursday and Friday, so newsrooms going home doesn't read as calm.
  - SITCON 1 also needs an event: one critical story on at least 10 outlets. Volume alone tops out at 2.
  - A new level shows only when two sweeps in a row call for it; until then the reason line says where it's heading.
  - The thresholds were fitted in November 2026 by replaying every hour from Oct 31 to Nov 10 with the current scoring: severe 13% of hours, elevated 60%, guarded 26%, quiet 1% (before: severe 45%). Refit them the same way if the scoring changes.

## Alerts

Set channels in `config.json` under `alerts.channels`:

| Key | What it sends |
|---|---|
| `slack_webhook` | A Slack incoming-webhook message |
| `teams_webhook` | An adaptive card to a Teams Workflows webhook ("When a Teams webhook request is received") |
| `discord_webhook` | A Discord webhook message |
| `ntfy_topic` (and `ntfy_server`) | A push to every phone subscribed to that ntfy topic |
| `webhook` | A JSON POST to any URL |
| `desktop` | A macOS notification on this Mac |

`alerts.min_severity` (default `critical`) sets the bar for new reports, and
`alerts.watchlist` lists names that alert at any severity:

```json
"alerts": {
  "min_severity": "critical",
  "watchlist": ["okta", "railway", "litellm", "fortigate"],
  "channels": { "slack_webhook": "https://hooks.slack.com/services/…" }
}
```

Environment variables override the file: `SM_SLACK_WEBHOOK`, `SM_TEAMS_WEBHOOK`,
`SM_DISCORD_WEBHOOK`, `SM_NTFY_TOPIC`, `SM_NTFY_SERVER`, `SM_WEBHOOK_URL`,
`SM_WATCHLIST` (comma-separated), `SM_MIN_SEVERITY`. Check your setup with:

```bash
python3 monitor.py --test-alert
```

The first sweep only records a baseline and alerts on nothing.

## The analyst (a Claude scheduled task)

The maintainer's Claude scheduled task **The Situation Monitor: hourly sweep** runs
once an hour while the Claude app is open. It sweeps nothing itself: there is one
pipeline (the GitHub sweep) and one memory (its Actions cache). Each run:

1. starts the GitHub sweep, then runs `monitor.py --from-site --wait 150`, which waits for that sweep to go live, downloads the published `changes.json`, `situation.json` with `more.json` (joined back into the whole board) and `live.json`, and reports as JSON what was first seen since the analyst last looked (its only memory is `state/analyst.json`)
2. rewrites the SITREP from `monitor.py --brief` (the published board as text) when there are new critical or high reports, the level changes, or the SITREP is over 6 hours old, and commits it here as `sitrep.json` (the push redeploys the site)
3. runs `monitor.py --apply-sitrep` and pushes the published `live.json`, carrying the new SITREP, into a private live copy of the site on claude.ai
4. sends the maintainer a push notification when something new is critical or on the watchlist

So every fact in a SITREP is already on the public board when it is written, and every
timestamp comes from GitHub's or the site's clocks, not the Mac's. A SITREP older than
36 hours is dropped from the site, so stale analysis never lingers.

## The archive

The board only keeps 14 days, and the sweep's memory lives in the Actions cache, which GitHub
evicts after 7 unused days. So after each sweep an `archive` job (the workflow's only part
with write access to the repository) runs `ops/archive.py save` and commits to the orphan
[`data` branch](../../tree/data):

- `sitreps/YYYY-MM-DD/HHMMSSZ.json`: every briefing, under its real UTC time
- `days/YYYY-MM-DD.json`: one snapshot per finished UTC day. It covers SITCON readings and hours at each level, the situations, the top critical and high reports, CISA KEV additions, breaches, ransomware claims by group, the archive-based counts, and that day's briefings.
- `state/`: the sweep's memory, refreshed once a day. A sweep that finds its cache empty restores from it (`ops/archive.py restore`) instead of starting from nothing.

Most sweeps add nothing; a commit lands for each new SITREP and once a day after midnight UTC.
Days from Oct 24 to Nov 10, 2026 and the earlier briefings were backfilled once with
`ops/archive.py backfill`, with the Mac's 3-hour clock error corrected; the branch's README says how.

## Run your own copy on GitHub Pages

1. Fork this repository. Pages is free on public repositories.
2. In the fork's **Actions** tab, turn workflows on (forks start with them off).
3. In **Settings → Pages → Build and deployment**, set the source to **GitHub Actions**.
4. In **Settings → Secrets and variables → Actions**, add any alert secrets (`SM_SLACK_WEBHOOK` and the rest), plus the variables `SM_SITE_URL` (for example `https://you.github.io/situation-monitor/`), `SM_REPO_URL` and `SM_WATCHLIST`.
5. Open **Actions → Situation Monitor sweep → Run workflow**. It then runs every 30 minutes.

Your copy's RSS feed is then at `<site>/data/feed.xml` and its master prompt at
`<site>/data/master-prompt.md`, so your team can subscribe or fetch it from its own tools.

Notes:

- The workflow keeps `state/` in the Actions cache, so sweeps never commit to the repository.
- GitHub pauses scheduled workflows in a public repository after 60 days without a commit. Any push turns it back on. Here the weekly Checks workflow commits a heartbeat after 30 quiet days, so it never gets that far.
- A fork shows the SITREP it was forked with until that goes stale. Delete `sitrep.json` or write your own.

## Caveats

- Scoring is keyword-based. It surfaces what to read first; it doesn't replace reading it.
- Ransomware entries are criminals' leak-site claims, not confirmed breaches.
- Several feeds keep only a day or two of history, so the days before the first sweep are partial. They fill in as the monitor runs.
- Confirm with the vendor advisory or the original report before acting.
