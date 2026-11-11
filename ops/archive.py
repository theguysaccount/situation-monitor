"""The permanent record on the `data` branch: every briefing, one snapshot per day, and the sweep's memory.

The sweep's memory lives in the Actions cache, which GitHub evicts after 7 days unused, and past briefings
were only git commits. This keeps both on an orphan branch, `data`, that is never deployed or merged:

  sitreps/YYYY-MM-DD/HHMMSSZ.json   every analyst briefing, as published
  days/YYYY-MM-DD.json              one snapshot per finished UTC day: SITCON readings, situations, top
                                    reports, CISA KEV additions, breaches, ransomware claim counts
  state/                            the sweep's memory, refreshed once a day, restored when the cache is empty

  python3 ops/archive.py save --state state --site site --archive archive [--sitrep sitrep.json]
  python3 ops/archive.py restore --state state --archive archive
  python3 ops/archive.py backfill --repo . --state <state dir> --published <situation.json> --runs <runs.json> --archive <dir>

Standard library only. Everything inside the files came from public feeds and is untrusted text.
"""
from __future__ import annotations

import argparse
import copy
import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import monitor as m  # noqa: E402

STATE_FILES = ("items.json", "seen.json", "meta.json", "history.json", "sources_status.json")
FIRST_DAY = "2026-10-24"  # the first sweep
TOP_REPORTS = 25


def day_bounds(day: str) -> tuple[datetime, datetime]:
    start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
    return start, start + timedelta(days=1)


def days_between(first: str, last: str) -> list[str]:
    out, d = [], datetime.fromisoformat(first).date()
    while d.isoformat() <= last:
        out.append(d.isoformat())
        d += timedelta(days=1)
    return out


def row(it: dict) -> dict:
    return dict(m.summary_row(it), first_seen=it.get("first_seen"), cves=(it.get("cves") or [])[:6])


def day_snapshot(day: str, items: list[dict], hist: dict, meta: dict, sitreps: list[str], source: str = "sweep",
                 note: str = "") -> dict:
    """What the board knew about one UTC day, written once the day is over."""
    start, end = day_bounds(day)
    seen = [it for it in items if (it.get("first_seen") or "")[:10] == day]
    readings = sorted(([r[0], r[1], r[2] if len(r) > 2 else None] for r in hist.get("sitcon", []) if str(r[0])[:10] == day),
                      key=lambda r: r[0])
    hours = {}
    for _, lv, _ in readings:
        hours[str(lv)] = hours.get(str(lv), 0) + 1
    reports = sorted((it for it in seen if it["severity"] in ("critical", "high") and it["type"] not in ("kev", "ransomware")),
                     key=lambda it: (m.SEV_RANK[it["severity"]], it.get("published") or ""), reverse=True)
    kev = [{"cve": (it.get("cves") or [""])[0], "vendor": (it.get("extra") or {}).get("vendor"),
            "product": (it.get("extra") or {}).get("product"), "title": it["title"], "url": it["url"],
            "due": (it.get("extra") or {}).get("due"), "ransomware": (it.get("extra") or {}).get("ransomware")}
           for it in items if it["type"] == "kev" and (it.get("published") or "")[:10] == day]
    claims = [it for it in items if it["type"] == "ransomware" and (it.get("published") or "")[:10] == day]
    groups: dict[str, int] = {}
    for it in claims:
        g = (it.get("extra") or {}).get("group") or "unknown"
        groups[g] = groups.get(g, 0) + 1
    breaches = [row(it) for it in items if it["type"] == "breach" and (it.get("published") or "")[:10] == day]
    # Situations as the board would have shown them at the end of the day (three or more outlets, 72 hours).
    window = [copy.deepcopy(it) for it in items
              if m.iso(start - timedelta(hours=72)) <= (it.get("published") or "") < m.iso(end)]
    try:
        situations = m.find_situations(window, {"now": end - timedelta(seconds=1), "vocab": set(meta.get("vocab", []))})
    except Exception as e:  # a snapshot without situations beats no snapshot
        situations, note = [], (note + f" Situations could not be computed: {type(e).__name__}.").strip()
    archive_row = {}
    try:
        series = m.history_series(hist, end - timedelta(seconds=1))
        archive_row = next((dict(zip(series["fields"], r)) for r in series["days"] if r[0] == day), {})
    except Exception:
        pass
    by_sev, by_type = {}, {}
    for it in seen:
        by_sev[it["severity"]] = by_sev.get(it["severity"], 0) + 1
        by_type[it["type"]] = by_type.get(it["type"], 0) + 1
    out = {
        "schema": 1, "date": day, "source": source,
        "sitcon": {"readings": readings, "hours_at_level": hours,
                   "highest": min((r[1] for r in readings), default=None),
                   "lowest": max((r[1] for r in readings), default=None)},
        "first_seen": {"count": len(seen), "by_severity": by_sev, "by_type": by_type},
        "situations": [{"name": s["name"], "severity": s["severity"], "outlets": s["source_count"], "reports": s["count"],
                        "cves": s.get("cves", []), "lead": s["lead"]} for s in situations],
        "top_reports": [row(it) for it in reports[:TOP_REPORTS]],
        "kev_added": kev,
        "breaches": breaches[:25],
        "ransomware_claims": {"count": len(claims),
                              "groups": sorted(([g, n] for g, n in groups.items()), key=lambda x: -x[1])[:10]},
        "archive_counts": archive_row,
        "sitreps": sitreps,
    }
    if note:
        out["note"] = note
    return out


def sitrep_path(archive: Path, written_at: str) -> Path:
    return archive / "sitreps" / written_at[:10] / (written_at[11:19].replace(":", "") + "Z.json")


def sitreps_on(archive: Path, day: str) -> list[str]:
    folder = archive / "sitreps" / day
    return sorted(f"sitreps/{day}/{p.name}" for p in folder.glob("*.json")) if folder.is_dir() else []


def write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def archive_sitrep(archive: Path, raw: dict, real: str) -> str | None:
    """File a briefing under its real time. sitreps/index.json maps each briefing's own stamp to its file,
    so the same briefing is never filed twice however its time was corrected."""
    recorded = str(raw.get("written_at") or "")
    if not m.parse_iso(recorded) or not m.parse_iso(real) or not raw.get("headline"):
        return None
    index_path = archive / "sitreps" / "index.json"
    index = m.load_json(index_path, {})
    path = sitrep_path(archive, real)
    if recorded in index or path.exists():
        return None
    out = dict(raw, written_at=real)
    if real != recorded:
        out["written_at_as_recorded"] = recorded
    write(path, out)
    index[recorded] = str(path.relative_to(archive))
    write(index_path, dict(sorted(index.items())))
    return index[recorded]


def save(state: Path, site: Path, archive: Path, sitrep: Path | None) -> list[str]:
    """Called after every sweep. Writes only what is missing, so most sweeps change nothing."""
    data = json.loads((site / "data" / "situation.json").read_text(encoding="utf-8"))
    today = data["generated_at"][:10]
    changed = []
    for src in filter(None, [sitrep, state / "sitrep.json"]):
        raw = m.load_json(src, None)
        if isinstance(raw, dict):
            # A briefing can't have been written after the sweep that publishes it (the analyst's clock ran fast).
            got = archive_sitrep(archive, raw, min(str(raw.get("written_at") or ""), data["generated_at"]))
            if got:
                changed.append(got)
    done = sorted(p.stem for p in (archive / "days").glob("*.json"))
    first = (datetime.fromisoformat(done[-1]).date() + timedelta(days=1)).isoformat() if done else \
        (datetime.fromisoformat(today).date() - timedelta(days=1)).isoformat()
    todo = [d for d in days_between(first, today) if d < today]
    if todo:
        items = (m.load_json(state / "items.json", {}) or {}).get("items", [])
        hist, meta = m.load_json(state / "history.json", {}), m.load_json(state / "meta.json", {})
        for day in todo:
            write(archive / "days" / f"{day}.json", day_snapshot(day, items, hist, meta, sitreps_on(archive, day)))
            changed.append(f"days/{day}.json")
    if todo or not (archive / "state" / "items.json").exists():
        for name in STATE_FILES:
            if (state / name).exists():
                (archive / "state").mkdir(parents=True, exist_ok=True)
                shutil.copyfile(state / name, archive / "state" / name)
        changed.append("state/")
    return changed


def restore(state: Path, archive: Path) -> bool:
    """Called before a sweep: if the cache came back empty, start from the archived memory instead of from zero."""
    if (state / "items.json").exists() or not (archive / "state" / "items.json").exists():
        return False
    state.mkdir(parents=True, exist_ok=True)
    for name in STATE_FILES:
        if (archive / "state" / name).exists():
            shutil.copyfile(archive / "state" / name, state / name)
    return True


# ---------------------------------------------------------------- one-off backfill (Oct 24 onwards)

def git(repo: Path, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def clock_window(commits: list[tuple[str, str]], pushed: dict[str, str]) -> tuple[str, str, float] | None:
    """From SITREP commits stamped by the Mac's clock and the times GitHub received them, find when the Mac
    ran fast: (first local stamp, last local stamp, skew in seconds)."""
    fast = []
    for sha, local in commits:
        if sha in pushed:
            skew = (m.parse_iso(local) - m.parse_iso(pushed[sha])).total_seconds()
            if skew > 1800:
                fast.append((local, skew))
    if not fast:
        return None
    fast.sort()
    skews = sorted(s for _, s in fast)
    return m.iso(m.parse_iso(fast[0][0]) - timedelta(hours=1)), fast[-1][0], skews[len(skews) // 2]


def backfill(repo: Path, state: Path, published: Path, runs: Path, archive: Path, until: str) -> list[str]:
    pushed = {}
    for r in json.loads(runs.read_text()):
        if r.get("event") == "push":
            sha = r["headSha"]
            pushed[sha] = min(pushed.get(sha, r["createdAt"]), r["createdAt"])
    commits = [line.split() for line in git(repo, "log", "--reverse", "--format=%H %cI", "origin/main", "--", "sitrep.json").splitlines()]
    commits = [(sha, m.iso(m.parse_iso(stamp))) for sha, stamp in commits]
    window = clock_window(commits, pushed)

    mac = m.load_json(state / "items.json", {}).get("items", [])
    hist = m.load_json(state / "history.json", {})
    meta = m.load_json(state / "meta.json", {})
    # SITCON readings are stored in the order the sweeps ran. The fast stretch starts inside the window the
    # commits give and ends where the stamps jump backwards (the Mac started measuring real time).
    readings = hist.get("sitcon", [])
    back = next((i for i in range(1, len(readings)) if readings[i][0] < readings[i - 1][0]), len(readings))
    fast_until = readings[back - 1][0] if back < len(readings) else (window[1] if window else "")

    def shift(stamp: str) -> str:
        return m.iso(m.parse_iso(stamp) - timedelta(seconds=window[2]))

    def fix(stamp: str | None) -> str | None:
        if stamp and window and window[0] <= stamp <= fast_until:
            return shift(stamp)
        return stamp

    hist["sitcon"] = sorted([shift(r[0]) if window and i < back and r[0] >= window[0] else r[0], *r[1:]]
                            for i, r in enumerate(readings))

    changed = []
    for sha, local in commits:
        try:
            raw = json.loads(git(repo, "show", f"{sha}:sitrep.json"))
        except (subprocess.CalledProcessError, ValueError):
            continue
        recorded = str(raw.get("written_at") or "")
        real = recorded
        if sha in pushed and recorded > m.iso(m.parse_iso(pushed[sha]) + timedelta(minutes=10)):
            real = pushed[sha]  # stamped by the fast clock: it can't have been written after GitHub received it
        got = archive_sitrep(archive, dict(raw, commit=sha, pushed_at=pushed.get(sha)), real)
        if got:
            changed.append(got)

    for it in mac:
        it["first_seen"] = fix(it.get("first_seen"))
    # The public board's own first-seen times (GitHub's clock, always real) win; the Mac's fill the gaps.
    board = {it["id"]: it for it in mac}
    for it in json.loads(published.read_text()).get("items", []):
        if it["id"] not in board or it.get("first_seen"):
            board[it["id"]] = it
    items = list(board.values())
    note = ("Backfilled on 2026-11-11 from the sweep memory kept on the analyst's Mac and the public board. Reports "
            "drop off the board 14 days after publication, so early days list fewer reports than were seen; the "
            "archive_counts come from the full CISA KEV, ransomware-claim, Have I Been Pwned and Hacker News archives.")
    if window:
        note += (f" The Mac's clock ran {window[2] / 3600:.1f} h fast from about {window[0]}; its stamps in that "
                 "period have been corrected.")
    for day in days_between(FIRST_DAY, until):
        path = archive / "days" / f"{day}.json"
        if not path.exists():
            write(path, day_snapshot(day, items, hist, meta, sitreps_on(archive, day), source="backfill", note=note))
            changed.append(f"days/{day}.json")
    return changed


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("save")
    s.add_argument("--state", type=Path, required=True)
    s.add_argument("--site", type=Path, required=True)
    s.add_argument("--archive", type=Path, required=True)
    s.add_argument("--sitrep", type=Path)
    r = sub.add_parser("restore")
    r.add_argument("--state", type=Path, required=True)
    r.add_argument("--archive", type=Path, required=True)
    b = sub.add_parser("backfill")
    b.add_argument("--repo", type=Path, required=True)
    b.add_argument("--state", type=Path, required=True)
    b.add_argument("--published", type=Path, required=True)
    b.add_argument("--runs", type=Path, required=True, help="gh run list --json headSha,createdAt,event output")
    b.add_argument("--archive", type=Path, required=True)
    b.add_argument("--until", required=True, help="last finished UTC day to write, YYYY-MM-DD")
    args = ap.parse_args(argv)
    if args.cmd == "restore":
        print("Restored state/ from the data branch." if restore(args.state, args.archive)
              else "State present (or nothing archived yet); nothing restored.")
        return 0
    if args.cmd == "save":
        changed = save(args.state, args.site, args.archive, args.sitrep)
    else:
        changed = backfill(args.repo, args.state, args.published, args.runs, args.archive, args.until)
    print(f"{len(changed)} archive changes" + (": " + ", ".join(changed[:12]) + (" …" if len(changed) > 12 else "") if changed else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
