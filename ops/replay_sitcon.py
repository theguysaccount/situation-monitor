"""Replay the SITCON level hour by hour from the items in state/, to fit or check level_thresholds.

The board keeps 14 days of items, so the replay covers roughly the last 10 days (each hour needs
a few days of history behind it). It scores every hour with the current rules, prints the heat
percentiles, and shows how often each level would be shown with the given thresholds, including
the two-sweeps-agree rule.

  python3 ops/replay_sitcon.py                       # thresholds from config.json
  python3 ops/replay_sitcon.py 250 290 405 430 -v    # try others; -v prints a level per hour
"""
import json
import sys
from collections import Counter
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import monitor as m  # noqa: E402


def replay(items: list, meta: dict) -> list:
    first = min(m.parse_iso(it["published"]) for it in items) + timedelta(days=4)
    t = first.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    end = m.now_utc()
    rows = []
    while t <= end:
        stamp = m.iso(t)
        now_items = [dict(it) for it in items if it["published"] <= stamp and m.hours_since(it["published"], t) <= 144]
        text = " ".join(f"{it['title']} {it['summary']}" for it in now_items
                        if it["type"] in ("news", "advisory", "community", "breach")).lower()
        ctx = {"now": t, "news_text": text, "vocab": set(meta.get("vocab", [])),
               "kev_cves": set(meta.get("kev_cves", [])), "seen": {}}
        for it in now_items:
            m.rescore(it, ctx)
        situations = m.find_situations(now_items, ctx)
        rows.append((t, m.compute_level(now_items, situations, t, [float("inf")] * 4)["heat"],
                     any(s["severity"] == "critical" and s["source_count"] >= m.EVENT_OUTLETS for s in situations)))
        t += timedelta(hours=1)
    return rows


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "-v"]
    cfg = json.loads((ROOT / "config.json").read_text())
    thresholds = [float(a) for a in args] if args else cfg.get("level_thresholds") or m.DEFAULT_THRESHOLDS
    m.measure_clock()  # replay up to the real time, not this machine's clock
    items = m.load_json(m.STATE / "items.json", {}).get("items", [])
    if not items:
        sys.exit("No items in state/; run a sweep first.")
    rows = replay(items, m.load_json(m.STATE / "meta.json", {}))
    heats = sorted(h for _, h, _ in rows)
    print(f"{len(rows)} hours, {m.iso(rows[0][0])} to {m.iso(rows[-1][0])}")
    print("heat percentiles: " + ", ".join(f"p{p} {heats[min(len(heats) - 1, len(heats) * p // 100)]:.0f}"
                                           for p in (5, 10, 25, 50, 75, 90, 95, 99)))
    shown = prev = None
    levels = []
    for t, heat, event in rows:
        want = 5
        for lv, th in zip((4, 3, 2, 1), thresholds):
            want = lv if heat >= th else want
        want = 2 if want == 1 and not event else want
        if shown is None or (want != shown and prev == want):
            shown = want
        prev = want
        levels.append((t, shown))
    for label, keep in (("all hours", lambda t: True), ("weekends", lambda t: t.weekday() >= 5),
                        ("weekdays", lambda t: t.weekday() < 5)):
        c = Counter(lv for t, lv in levels if keep(t))
        total = sum(c.values()) or 1
        print(f"{label:10} " + "  ".join(f"{lv} {m.LEVELS[lv][0].lower()} {100 * c[lv] / total:3.0f}%" for lv in (1, 2, 3, 4, 5)))
    if "-v" in sys.argv:
        day = None
        for t, lv in levels:
            if t.date() != day:
                day = t.date()
                print(f"\n{day} {t.strftime('%a')} ", end="")
            print(lv, end="")
        print()


if __name__ == "__main__":
    main()
