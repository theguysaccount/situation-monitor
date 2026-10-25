#!/usr/bin/env python3
"""Live health and staleness check for the public board. Read-only unless --heal.

  python3 ops/health.py            check the live site; exit 1 with ::error:: annotations on failure
  python3 ops/health.py --heal     also dispatch a sweep when the data is overdue and none is queued
                                   (needs GITHUB_TOKEN with actions: write)

GitHub drops many scheduled runs of a busy cron, so the 30-minute sweep often lands hours apart.
This check runs on its own schedule and, with --heal, starts a sweep itself whenever the live
data is older than HEAL_AFTER_MINUTES. It fails loudly when the data is older than
FAIL_AFTER_HOURS, when the page or feed is broken, or when too few sources answer. The last good
deploy is never touched.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import UA, Checks, fetch, github_api, sitemap_locs, tls_days_left  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = "situation-monitor.yml"
HEAL_AFTER_MINUTES = 75
WARN_AFTER_HOURS, FAIL_AFTER_HOURS = 2, 6
WARN_SOURCE_SHARE, FAIL_SOURCE_SHARE = 0.8, 0.6
SITREP_WARN_HOURS = 36   # the site drops an analyst SITREP older than this
TLS_WARN_DAYS, TLS_FAIL_DAYS = 21, 10


def site_url() -> str:
    url = os.environ.get("SM_SITE_URL") or json.loads((ROOT / "config.json").read_text())["site_url"]
    return url if url.endswith("/") else url + "/"


def hours_ago(stamp: str) -> float:
    dt = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds() / 3600


def dispatch_sweep(c: Checks, repo: str) -> None:
    status, runs = github_api(f"repos/{repo}/actions/workflows/{WORKFLOW}/runs?per_page=10")
    if status != 200:
        return c.warn("self-heal", f"could not list sweep runs (HTTP {status}); no sweep started")
    busy = [r for r in runs.get("workflow_runs", []) if r.get("status") in ("queued", "in_progress", "waiting", "pending")]
    if busy:
        return c.ok("self-heal", f"a sweep is already {busy[0]['status']} (run {busy[0]['id']})")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/actions/workflows/{WORKFLOW}/dispatches",
        data=json.dumps({"ref": "main"}).encode(), method="POST",
        headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "User-Agent": UA,
                 "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            c.ok("self-heal", f"data was overdue; dispatched a sweep (HTTP {r.status})")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
        c.warn("self-heal", f"could not dispatch a sweep: {e}")


def check(heal: bool) -> int:
    site = site_url()
    host = urlsplit(site).netloc
    c = Checks(f"{host} health")

    status, _, _, body, err = fetch(site, tries=3)
    if status == 200 and b"The Situation Monitor" in body:
        c.ok("home page")
    else:
        c.fail("home page", f"HTTP {status} {err}".strip() if status != 200 else "200 but the page lacks its title")

    status, _, _, body, err = fetch(site + "data/situation.json", tries=3, limit=20_000_000)
    data = None
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError as e:
            c.fail("data/situation.json", f"not JSON: {e}")
    else:
        c.fail("data/situation.json", f"HTTP {status} {err}".strip())
    if data:
        age = hours_ago(data["generated_at"])
        detail = f"last sweep {age * 60:.0f} min ago ({data['generated_at']})"
        if age > FAIL_AFTER_HOURS:
            c.fail("data freshness", detail + f"; over {FAIL_AFTER_HOURS} h. Check the sweep workflow's recent runs.")
        elif age > WARN_AFTER_HOURS:
            c.warn("data freshness", detail)
        else:
            c.ok("data freshness", detail)
        if heal and age * 60 > HEAL_AFTER_MINUTES:
            dispatch_sweep(c, os.environ.get("GITHUB_REPOSITORY", "theguysaccount/situation-monitor"))

        stats = data.get("stats") or {}
        ok, total = stats.get("sources_ok", 0), stats.get("sources_total", 0) or 1
        failing = ", ".join(f"{s['name']} ({s.get('error') or 'error'})" for s in data.get("sources", []) if not s.get("ok"))
        share = ok / total
        if share < FAIL_SOURCE_SHARE:
            c.fail("sources answering", f"{ok}/{total}; failing: {failing}")
        elif share < WARN_SOURCE_SHARE or failing:
            c.warn("sources answering", f"{ok}/{total}; failing: {failing}")
        else:
            c.ok("sources answering", f"{ok}/{total}")
        (c.ok if data.get("items") else c.fail)("board has items", f"{len(data.get('items') or [])} items")

        sitrep = data.get("sitrep")
        if sitrep and sitrep.get("written_at"):
            c.ok("analyst SITREP", f"written {hours_ago(sitrep['written_at']):.0f} h ago")
        else:  # optional: written by a Claude scheduled task on the owner's Mac
            c.warn("analyst SITREP", f"none from the last {SITREP_WARN_HOURS} h; the board runs without it")

    status, _, _, body, err = fetch(site + "data/feed.xml", tries=3)
    try:
        root = ET.fromstring(body) if status == 200 else None
        (c.ok if root is not None and root.tag == "rss" else c.fail)("RSS feed", f"{len(root.findall('./channel/item'))} items" if root is not None else f"HTTP {status} {err}")
    except ET.ParseError as e:
        c.fail("RSS feed", f"not valid XML: {e}")

    status, _, _, body, err = fetch(site + "data/master-prompt.md", tries=3)
    if status == 200 and b"<situation_data" in body:
        c.ok("master prompt")
    else:
        c.fail("master prompt", f"HTTP {status} {err}".strip() if status != 200 else "no <situation_data> block")

    status, _, _, body, err = fetch(site + "robots.txt", tries=3)
    (c.ok if status == 200 and b"Sitemap:" in body else c.fail)("robots.txt", f"HTTP {status}")
    status, _, _, body, err = fetch(site + "sitemap.xml", tries=3)
    kind, locs = sitemap_locs(body) if status == 200 else ("", [])
    (c.ok if kind == "urlset" and site in locs else c.fail)("sitemap.xml", f"HTTP {status}, {len(locs)} URL(s)")

    keys = [p for p in (ROOT / "site").glob("*.txt") if len(p.stem) == 32]
    if keys:
        status, _, _, body, err = fetch(site + keys[0].name, tries=3)
        ok = status == 200 and body.decode("utf-8", "replace").strip() == keys[0].stem
        (c.ok if ok else c.fail)("IndexNow key file", f"HTTP {status}")

    if site.startswith("https://"):
        try:
            days = tls_days_left(host)
            if days < TLS_FAIL_DAYS:
                c.fail("TLS certificate", f"expires in {days:.1f} days; GitHub Pages should have renewed it")
            elif days < TLS_WARN_DAYS:
                c.warn("TLS certificate", f"expires in {days:.1f} days; GitHub Pages normally renews about 30 days ahead")
            else:
                c.ok("TLS certificate", f"{days:.0f} days left")
        except Exception as e:
            c.fail("TLS certificate", f"{type(e).__name__}: {e}")
    return c.finish()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Live health and staleness check for the public board.")
    ap.add_argument("--heal", action="store_true", help="dispatch a sweep when the data is overdue")
    return check(ap.parse_args(argv).heal)


if __name__ == "__main__":
    sys.exit(main())
