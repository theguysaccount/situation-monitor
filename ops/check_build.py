#!/usr/bin/env python3
"""Pre-deploy gate: refuse to publish a site/ that the sweep left broken or stale.

Runs in the sweep workflow after monitor.py and before the Pages upload. Any failure exits 1,
so the deploy never runs and the last good deploy stays live; the ::error:: annotations on the
run page say why.

  python3 ops/check_build.py            check site/
  python3 ops/check_build.py --dir D    check another directory (tests)

Standard library only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import gzip
import html
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Checks  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MAX_AGE_MINUTES = 30      # the sweep that just ran must have produced the data
MIN_SOURCE_SHARE = 0.6    # below this, too much of the board would be stale or missing
STORE_LIMIT = 256 * 1024  # the claude.ai live store refuses documents over 256 KiB
FIRST_LOAD_BUDGET = 150_000  # gzip bytes for index.html plus data/situation.json (monitor.py fits the data to it)
STATIC_REPORTS = 20       # report links monitor.py writes into index.html


def age_minutes(stamp: str, skew_seconds: float = 0.0) -> float:
    """Minutes since stamp, on the clock the sweep measured (its recorded offset from real time)."""
    dt = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) + timedelta(seconds=skew_seconds) - dt).total_seconds() / 60


def run(site: Path) -> int:
    c = Checks("Pre-deploy gate")
    index = site / "index.html"
    page = index.read_text(encoding="utf-8") if index.exists() else ""
    if len(page) > 10_000 and "The Situation Monitor" in page and 'rel="canonical"' in page:
        c.ok("index.html", f"{len(page):,} bytes")
    else:
        c.fail("index.html", "missing, too small, or without its title and canonical link")

    try:
        data = json.loads((site / "data" / "situation.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        c.fail("data/situation.json", f"unreadable: {e}")
        return c.finish()
    try:
        age = age_minutes(data["generated_at"], float((data.get("clock") or {}).get("skew_seconds", 0)))
        (c.ok if age <= MAX_AGE_MINUTES else c.fail)("data is fresh", f"generated {age:.0f} min ago ({data['generated_at']})")
    except (KeyError, ValueError) as e:
        c.fail("data is fresh", f"no usable generated_at: {e}")
    items = data.get("items") or []
    (c.ok if items else c.fail)("board has items", f"{len(items)} items")
    stats = data.get("stats") or {}
    ok, total = stats.get("sources_ok", 0), stats.get("sources_total", 0)
    failing = [s.get("name") for s in data.get("sources", []) if not s.get("ok")]
    if total and ok / total >= MIN_SOURCE_SHARE:
        c.ok("sources answering", f"{ok}/{total}" + (f"; failing: {', '.join(failing)}" if failing else ""))
    else:
        c.fail("sources answering", f"only {ok}/{total}; failing: {', '.join(failing) or 'unknown'}")
    if not data.get("site_url", "").startswith("https://"):
        c.fail("site_url", f"not an https URL: {data.get('site_url')!r}")

    live = site / "data" / "live.json"
    if live.exists() and live.stat().st_size <= STORE_LIMIT:
        c.ok("data/live.json", f"{live.stat().st_size:,} bytes")
    else:
        c.fail("data/live.json", "missing or over the 256 KiB live-store limit")
    try:  # the analyst on the Mac alerts and briefs from this file
        changes = json.loads((site / "data" / "changes.json").read_text(encoding="utf-8"))
        if changes.get("generated_at") != data.get("generated_at") or not isinstance(changes.get("items"), list):
            raise ValueError("not from this sweep")
        c.ok("data/changes.json", f"{len(changes['items'])} critical and high items")
    except (OSError, ValueError) as e:
        c.fail("data/changes.json", f"missing or unusable: {e}")
    more = data.get("more")
    if more:  # the page fetches the rest of the board from here the first time a view needs it
        try:
            rest = json.loads((site / "data" / "more.json").read_text(encoding="utf-8"))
            if rest.get("generated_at") != data.get("generated_at") or not isinstance(rest.get("items"), list):
                raise ValueError("not from this sweep")
            if len(rest["items"]) != more.get("items") or len(rest.get("packages") or []) != more.get("packages"):
                raise ValueError("its item or package count differs from what data/situation.json says it holds")
            c.ok("data/more.json", f"{len(rest['items'])} more items")
        except (OSError, ValueError) as e:
            c.fail("data/more.json", f"missing or unusable: {e}")

    # Warnings only: the page still works without these, and an older deploy would be worse.
    board = (site / "data" / "situation.json").read_bytes()
    first = len(gzip.compress(page.encode("utf-8"), 6)) + len(gzip.compress(board, 6))
    (c.ok if first <= FIRST_LOAD_BUDGET else c.warn)(
        "first load", f"{first / 1000:.0f} KB compressed for the page and data/situation.json (budget {FIRST_LOAD_BUDGET // 1000} KB)")
    markup = page.split("<script>")[0]
    reports = markup.count('class="row-title"')
    priority = ((more or {}).get("counts") or {}).get("priority")
    if priority is None:
        priority = sum(1 for it in items if it.get("severity") in ("critical", "high"))
    want = min(STATIC_REPORTS, priority)
    sitrep = (data.get("sitrep") or {}).get("headline")
    if reports < want:
        c.warn("page content without JavaScript", f"{reports} report links in index.html; expected {want}")
    elif sitrep and html.escape(sitrep, quote=True) not in markup:
        c.warn("page content without JavaScript", "the analyst briefing is missing from index.html")
    else:
        c.ok("page content without JavaScript", f"{reports} report links" + (" and the briefing" if sitrep else ""))

    for name, root_tag in (("data/feed.xml", "rss"), ("sitemap.xml", "urlset")):
        try:
            tag = ET.parse(site / name).getroot().tag.rsplit("}", 1)[-1]
            (c.ok if tag == root_tag else c.fail)(name, f"root <{tag}>")
        except (OSError, ET.ParseError) as e:
            c.fail(name, f"not valid XML: {e}")

    prompt = site / "data" / "master-prompt.md"
    text = prompt.read_text(encoding="utf-8") if prompt.exists() else ""
    if "<situation_data" in text and "{{" not in text and text.count("</situation_data") == 1:
        c.ok("data/master-prompt.md", f"{len(text):,} chars")
    elif text.count("</situation_data") > 1:
        c.fail("data/master-prompt.md", "more than one closing </situation_data> tag: feed text is escaping the data block")
    else:
        c.fail("data/master-prompt.md", "missing, without its <situation_data> block, or with unfilled {{placeholders}}")

    robots = (site / "robots.txt").read_text(encoding="utf-8") if (site / "robots.txt").exists() else ""
    (c.ok if "Sitemap: " in robots else c.fail)("robots.txt", "lists the sitemap" if "Sitemap: " in robots else "missing or no Sitemap line")

    keys = [p for p in site.glob("*.txt") if len(p.stem) == 32 and p.read_text().strip() == p.stem]
    (c.ok if keys else c.fail)("IndexNow key file", keys[0].name if keys else "missing from site/")
    return c.finish()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Refuse to deploy a broken or stale site/.")
    ap.add_argument("--dir", type=Path, default=ROOT / "site")
    return run(ap.parse_args(argv).dir)


if __name__ == "__main__":
    sys.exit(main())
