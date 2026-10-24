# The Situation Monitor

*"I am monitoring the situation."*

One page that pulls together the hacks, breaches, exploited vulnerabilities and
supply-chain attacks happening right now. It scores them, groups the stories
several outlets are covering into developing situations, and turns all of it
into a master prompt your team can paste into Claude to check its own exposure.

- **Live site:** https://theguysaccount.github.io/situation-monitor/
- **RSS of critical and high reports:** https://theguysaccount.github.io/situation-monitor/data/feed.xml
- **Master prompt with today's data:** https://theguysaccount.github.io/situation-monitor/data/master-prompt.md
- **Updates:** every 30 minutes through GitHub Actions. The analyst briefing (SITREP) is written by a Claude scheduled task and committed as `sitrep.json`.

## What's here

| File | What it does |
|---|---|
| `monitor.py` | The sweep. Fetches every source, normalises and de-duplicates, scores severity, groups developing situations, works out the SITCON level, writes `site/data/`, sends alerts. Python 3.9+, standard library only. |
| `sources.json` | The source list. Add or remove feeds here. |
| `config.json` | Alert channels, watchlist, SITCON thresholds, public site URL. |
| `MASTER_PROMPT.md` | The master prompt template that the site and the sweep fill with live data. |
| `site/app.html` | The website, one file. `site/index.html` is generated from it for static hosting. |
| `.github/workflows/situation-monitor.yml` | Public deploy: sweep every 30 minutes and publish to GitHub Pages. |
| `sitrep.json` | The latest analyst briefing, committed by the scheduled task so the public site shows it. |
| `state/` | The monitor's memory: what it has seen and alerted on. Not committed; the workflow keeps it in the Actions cache. |

## Run it

```bash
python3 monitor.py
```

```bash
python3 -m http.server 8765 --directory site
```

Then open http://localhost:8765. Other modes: `--summary` (JSON summary for
automation), `--brief` (the current situation as text), `--rebuild` (re-render
from the last sweep without fetching), `--no-alerts`, `--test-alert`.

Each sweep writes:

- `site/data/situation.json`: everything the website shows
- `site/data/live.json`: the same, trimmed to fit the live site's 256 KB store
- `site/data/feed.xml`: RSS of critical and high-severity reports
- `site/data/master-prompt.md`: the master prompt filled with the latest data, ready to paste
- `site/data/new.json`: what is new since the previous sweep

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

- **Severity** comes from the headline (summary-only words count half): active exploitation, zero-days, supply-chain compromise, worms, emergency patches, nation-state attribution, breaches with credentials, big record counts. Commentary, sponsored posts and weekly roundups are capped at medium.
- **CISA KEV entries** are critical for 72 hours after they're added, or for as long as they're tied to ransomware; high after that.
- **Have I Been Pwned breaches** are critical at 10M+ accounts and high at 1M+.
- **Developing situations** are names and CVEs that at least three outlets carried in the last 72 hours (two, if one is CISA KEV), merged when they share most of their reports.
- **SITCON** sums the last 48 hours of weighted reports (plus KEV additions and widely covered stories) and maps the total through `level_thresholds` in `config.json`: 5 quiet, 4 guarded, 3 elevated, 2 severe, 1 critical.

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
once an hour while the Claude app is open. Each run:

1. runs `monitor.py --summary`
2. rewrites the SITREP when there are new critical or high reports, the level changes, or the SITREP is over 6 hours old, and commits it here as `sitrep.json` (the push redeploys the site)
3. pushes the data into a private live copy of the site on claude.ai
4. sends the maintainer a push notification when something new is critical or on the watchlist

A SITREP older than 36 hours is dropped from the site, so stale analysis never lingers.

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
- GitHub pauses scheduled workflows in a public repository after 60 days without a commit. Any push turns it back on.
- A fork shows the SITREP it was forked with until that goes stale. Delete `sitrep.json` or write your own.

## Caveats

- Scoring is keyword-based. It surfaces what to read first; it doesn't replace reading it.
- Ransomware entries are criminals' leak-site claims, not confirmed breaches.
- Several feeds keep only a day or two of history, so the days before the first sweep are partial. They fill in as the monitor runs.
- Confirm with the vendor advisory or the original report before acting.
