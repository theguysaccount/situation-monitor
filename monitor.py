#!/usr/bin/env python3
"""The Situation Monitor: one picture of the hacks, breaches and exploited bugs happening now.

Sweeps public sources (security news RSS, CISA KEV, ransomware leak-site
trackers, Have I Been Pwned, GitHub's malware advisories, Hacker News),
normalises everything into one incident list, scores severity, groups the
stories several outlets are covering into "developing situations", works out
the SITCON level, writes the website's data files and alerts on new incidents.
Standard library only; Python 3.9+.

  python3 monitor.py                 sweep, rebuild the site data, send alerts
  python3 monitor.py --summary       same, then print a compact JSON summary
  python3 monitor.py --brief         print the current situation as text (no network)
  python3 monitor.py --rebuild       rebuild outputs from the last sweep (no network)
  python3 monitor.py --no-alerts     sweep without sending alerts
  python3 monitor.py --test-alert    send a test message to every configured channel
  python3 monitor.py --save-db-version N   record the live-store version after a sync
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

ROOT = Path(__file__).resolve().parent
SITE = ROOT / "site"
DATA = SITE / "data"
STATE = ROOT / "state"

UA = "Mozilla/5.0 (Macintosh) SituationMonitor/1.0 (+public threat-feed aggregator)"
WINDOW_DAYS = 14          # how long an incident stays on the board
PACKAGE_DAYS = 7          # how long a malicious package stays listed
STORE_BUDGET = 225_000    # bytes; the website's live store refuses documents over 256 KiB

SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {"low": 0.0, "medium": 0.6, "high": 2.5, "critical": 6.0}
LEVELS = {
    5: ("QUIET", "Background noise. Still monitoring."),
    4: ("GUARDED", "Routine incidents. Keep patching on schedule."),
    3: ("ELEVATED", "Active campaigns. Check your exposure this week."),
    2: ("SEVERE", "Mass exploitation or major breaches underway. Act today."),
    1: ("CRITICAL", "Internet-scale incident. Drop everything and monitor the situation."),
}
DEFAULT_THRESHOLDS = [35, 80, 140, 260]  # heat needed for SITCON 4, 3, 2 and 1


# ---------------------------------------------------------------- small helpers

def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})?$")


def parse_iso(s: str) -> datetime | None:
    m = ISO_RE.match((s or "").strip())
    if not m:
        return None
    y, mo, d, hh, mi, ss, frac, tz = m.groups()
    tzinfo = timezone.utc
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        tzinfo = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4])))
    try:
        return datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0),
                        int((frac[1:] + "000000")[:6]) if frac else 0, tzinfo=tzinfo)
    except ValueError:
        return None


def parse_date(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    if not s[:4].isdigit():
        try:
            dt = parsedate_to_datetime(s)
            if dt is not None:
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            pass
    return parse_iso(s)


def hours_since(stamp: str, now: datetime) -> float:
    dt = parse_iso(stamp)
    return (now - dt).total_seconds() / 3600 if dt else 1e9


def load_json(path: Path, default):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def save_json(path: Path, obj, compact: bool = False) -> None:
    if compact:
        save_text(path, json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    else:
        save_text(path, json.dumps(obj, ensure_ascii=False, indent=1))


TAG_RE = re.compile(r"<[^>]+>")
BOILERPLATE_RE = re.compile(r"(The post .{0,200}? appeared first on .{0,80}$|Continue reading.{0,60}$|Read more.{0,40}$|\[…\]|\[\.\.\.\])", re.I)


def clean(s: str, limit: int = 320) -> str:
    """Plain text from feed HTML, trimmed at a word boundary."""
    if not s:
        return ""
    s = html.unescape(TAG_RE.sub(" ", html.unescape(str(s)))).replace("�", "")
    s = BOILERPLATE_RE.sub("", re.sub(r"\s+", " ", s)).strip()
    if len(s) > limit:
        s = s[:limit].rsplit(" ", 1)[0].rstrip(",;:.-– ") + "…"
    return s


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


TRACKING = ("utm_", "fbclid", "gclid", "mc_cid", "mc_eid", "cmpid", "rss", "ref_src", "_hsenc", "_hsmi")


def strip_tracking(url: str) -> str:
    try:
        p = urllib.parse.urlsplit((url or "").strip())
    except ValueError:
        return ""
    if p.scheme not in ("http", "https") or not p.netloc or p.netloc.lower().endswith(".onion"):
        return ""
    q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
         if not k.lower().startswith(TRACKING)]
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(q), p.fragment))


def canon_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    host = p.netloc.lower()
    host = host[4:] if host.startswith("www.") else host
    path = p.path[:-4] if p.path.endswith("/amp/") else p.path
    return f"{host}{path.rstrip('/') or '/'}" + (f"?{p.query}" if p.query else "")


def uniq(seq):
    out = []
    for x in seq:
        if x and x not in out:
            out.append(x)
    return out


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


# ---------------------------------------------------------------- network

def http(url: str, data: bytes | None = None, headers: dict | None = None, timeout: int = 25) -> bytes:
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        hdrs["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    req = urllib.request.Request(url, data=data, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch(url: str, accept: str = "*/*") -> bytes:
    last: Exception = RuntimeError("no attempt")
    for attempt in range(2):
        try:
            return http(url, headers={"Accept": accept})
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (400, 401, 403, 404, 410, 451):
                break
        except Exception as e:  # timeouts, resets, TLS hiccups
            last = e
        time.sleep(1.5)
    raise last


def fetch_json(url: str):
    return json.loads(fetch(url, "application/json"))


# ---------------------------------------------------------------- feed parsing

def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _text(el, *names) -> str:
    for c in el:
        if _local(c.tag) in names:
            txt = (c.text or "").strip() or "".join(c.itertext()).strip()
            if txt:
                return txt
    return ""


def _atom_link(el) -> str:
    fallback = ""
    for c in el:
        if _local(c.tag) != "link":
            continue
        href = c.get("href")
        if href and c.get("rel", "alternate") == "alternate":
            return href
        if href and not fallback:
            fallback = href
        if not href and (c.text or "").strip().startswith("http"):
            return c.text.strip()
    return fallback


ENTRY_RE = re.compile(r"<(item|entry)\b[^>]*>(.*?)</\1\s*>", re.S | re.I)


def _loose_field(block: str, *names) -> str:
    for n in names:
        m = re.search(rf"<{n}\b[^>]*>(.*?)</{n}\s*>", block, re.S | re.I)
        if m:
            v = re.sub(r"^\s*<!\[CDATA\[(.*?)\]\]>\s*$", r"\1", m.group(1), flags=re.S).strip()
            if v:
                return v
    return ""


def parse_feed_loose(text: str) -> list[dict]:
    """Last resort for feeds that are not well-formed XML: pull entries out with patterns."""
    entries = []
    for _, block in ENTRY_RE.findall(text):
        m = re.search(r"<link\b[^>]*href=[\"']([^\"']+)[\"']", block, re.I)
        link = html.unescape(m.group(1)) if m else html.unescape(_loose_field(block, "link"))
        if not link.startswith("http"):
            guid = html.unescape(_loose_field(block, "guid", "id"))
            link = guid if guid.startswith("http") else ""
        entries.append({
            "title": html.unescape(_loose_field(block, "title")),
            "link": link,
            "summary": _loose_field(block, "description", "summary", "content:encoded", "content"),
            "date": _loose_field(block, "pubDate", "published", "dc:date", "updated"),
        })
    return entries


def parse_feed(raw: bytes) -> list[dict]:
    """RSS 2.0, RSS 1.0 and Atom entries as plain dicts, tolerating sloppy XML."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        text = raw.decode("utf-8", "replace")
        text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
        text = re.sub(r"&(?!(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);)", "&amp;", text)
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return parse_feed_loose(text)
    entries = []
    for el in root.iter():
        kind = _local(el.tag)
        if kind not in ("item", "entry"):
            continue
        link = _text(el, "link") if kind == "item" else ""
        if not link.startswith("http"):
            link = _atom_link(el) or ""
        if not link:
            guid = _text(el, "guid", "id")
            link = guid if guid.startswith("http") else ""
        entries.append({
            "title": _text(el, "title"),
            "link": link,
            "summary": _text(el, "description", "summary") or _text(el, "encoded", "content"),
            "date": _text(el, "pubdate", "published", "date", "updated", "issued", "modified"),
        })
    return entries


# ---------------------------------------------------------------- scoring

def _rx(p: str):
    return re.compile(p, re.I)


RULES = [  # (pattern, points, tag)
    (_rx(r"actively exploit|exploited in the wild|in-the-wild|under active (?:attack|exploitation)|mass[- ]exploit|being exploited|exploit(?:ation)? attempts|exploited (?:zero|0)[- ]?day|zero-day exploited"), 3, "actively-exploited"),
    (_rx(r"\bzero[- ]?days?\b|\b0[- ]?days?\b"), 3, "zero-day"),
    (_rx(r"supply[- ]chain|malicious (?:package|version|release|update|extension|npm|pypi)|compromised (?:package|release|pipeline|build|version|account|maintainer)|typosquat|dependency confusion|release pipeline|hijacked (?:package|account)"), 4, "supply-chain"),
    (_rx(r"\bworm\b|self-propagat|\bwiper\b"), 3, "worm"),
    (_rx(r"emergency (?:patch|fix|directive|update)|out-of-band|patch now|urgent(?:ly)? patch"), 2, "emergency"),
    (_rx(r"nation[- ]state|state-sponsored|state-backed|\bapt ?\d*\b|china-linked|china-nexus|russia-linked|north korea|iranian|lazarus|typhoon|sandworm|kimsuky|fancy bear|cozy bear"), 2, "nation-state"),
    (_rx(r"ransomware|extortion|leak site|encrypted (?:files|systems|servers)"), 2, "ransomware"),
    (_rx(r"data breach|\bbreach(?:ed|es)?\b|\bhacked\b|hackers? (?:stole|steal|accessed|breached|leaked|hijack)|stolen data|data (?:leak|theft|exposure)|exposed (?:data|records|database|secrets|credentials)|exposure of|\bleak(?:ed|s)?\b|exfiltrat|unauthori[sz]ed (?:access|party)|cyberattack|cyber-attack|cyber attack|security incident|\bcompromised\b"), 2, "breach"),
    (_rx(r"remote code execution|\brce\b|code execution|authentication bypass|auth bypass|privilege escalation|unauthenticated|sql injection|command injection"), 1, "rce"),
    (_rx(r"credential|password|api keys?|secrets?\b|tokens?\b|environment variables|session cookies|private keys"), 1, "credentials"),
    (_rx(r"backdoor|infostealer|info-stealer|stealer|trojan|botnet|rootkit|malware|spyware|\brat\b|loader"), 1, "malware"),
    (_rx(r"phishing|smishing|vishing|social engineering|impersonat|help ?desk"), 1, "phishing"),
    (_rx(r"\bddos\b|denial[- ]of[- ]service"), 1, "ddos"),
    (_rx(r"critical(?:\s+[\w.'-]+){0,2}?\s+(?:flaws?|vulnerabilit|bugs?|security|infrastructure|rce)|cvss(?: v?\d(?:\.\d)?)?(?: score)?(?: of)? (?:9\.\d|10)"), 2, "critical"),
    (_rx(r"vulnerabilit|\bflaws?\b|\bbugs?\b|\bpatch(?:es|ed)?\b|security update|advisory|\bcve-"), 1, "vuln"),
    (_rx(r"hospital|healthcare|health system|patients?\b|medical|pharma"), 1, "healthcare"),
    (_rx(r"power grid|water (?:utility|system)|critical infrastructure|\bics\b|scada|\bot (?:network|systems)|energy sector|pipeline operator"), 1, "critical-infra"),
    (_rx(r"crypto(?:currency)?|bitcoin|ethereum|defi\b|wallet drainer|exchange (?:hack|heist)"), 1, "crypto"),
    (_rx(r"\bai\b|\bllms?\b|openai|anthropic|claude|chatgpt|\bgpt|gemini|copilot|agentic|ai agents?|mcp server|inference|litellm|hugging ?face"), 0, "ai"),
    (_rx(r"\baws\b|azure|google cloud|\bgcp\b|kubernetes|\bk8s\b|cloud"), 0, "cloud"),
    (_rx(r"okta|entra|active directory|\bsso\b|oauth|\bmfa\b|identity provider"), 0, "identity"),
    (_rx(r"arrest|charged|sentenced|extradit|takedown|seized|dismantl|indicted|pleads? guilty|europol"), 0, "law-enforcement"),
]
NEGATIVE = _rx(r"webinar|podcast|sponsored|\bdeal\b|funding|raises \$|acquir|acquisition|partnership|appoints?|\bhires\b|named (?:ciso|ceo|cto)|\baward|conference|keynote|\bhow to\b|\bguide\b|review:|best .{0,30}(?:apps|tools|vpns?)|interview|opinion|product (?:launch|showcase)|weekly recap|week in review|newsletter|\bjobs?\b|careers|survey finds|report finds|\bstudy\b|predictions|\bcoupon|\bsale\b")
ROUNDUP = _rx(r"in other news|round-?up|threatsday|weekly recap|week in review|this week in|news brief|recap:|daily briefing|top stories")
BIG_NUM = _rx(r"(\$?)(\d+(?:\.\d+)?)\s*(million|billion|bn\b|m\b)")


def keyword_score(title: str, summary: str = "") -> tuple[float, list[str]]:
    """Headline words count in full, summary-only words count half.

    A headline with no signal of its own (commentary, sponsored posts) and
    roundup posts never score above medium, however busy their summaries are.
    """
    tl, sl = title.lower(), summary.lower()
    score, tags, headline = 0.0, [], 0
    for rx, pts, tag in RULES:
        if rx.search(tl):
            score += pts
            headline += pts
            tags.append(tag)
        elif rx.search(sl):
            score += pts / 2
            tags.append(tag)
    biggest = 0.0
    for dollar, num, unit in BIG_NUM.findall(f"{tl} {sl}"):
        if unit.lower() == "m" and not dollar:
            continue
        biggest = max(biggest, float(num) * (1e9 if unit.lower().startswith("b") else 1e6))
    score += 2 if biggest >= 50e6 else 1 if biggest >= 1e6 else 0
    if "breach" in tags and "credentials" in tags:
        score += 1
    if NEGATIVE.search(tl) or ROUNDUP.search(tl):
        score -= 3
    elif NEGATIVE.search(sl):
        score -= 1
    if headline == 0 or ROUNDUP.search(tl):
        score = min(score, 2.9)
    return score, tags


def sev_from_score(score: float) -> str:
    return "critical" if score >= 6 else "high" if score >= 3 else "medium" if score >= 1 else "low"


def bump(sev: str, steps: int) -> str:
    return SEVERITIES[max(0, min(3, SEV_RANK[sev] + steps))]


SECTOR_TAGS = {"healthcare": "healthcare", "hospital": "healthcare", "government": "government",
               "public sector": "government", "education": "education", "energy": "critical-infra",
               "utilities": "critical-infra", "financial": "finance", "banking": "finance"}


def rescore(it: dict, ctx: dict) -> None:
    """Set severity and tags from the stored fields, so rule changes apply to old items too."""
    t, ex = it["type"], it.get("extra") or {}
    score, tags = keyword_score(it["title"], it.get("summary", ""))
    if t == "kev":
        sev = "critical" if ex.get("ransomware") or hours_since(it["published"], ctx["now"]) <= 72 else "high"
        tags = ["actively-exploited"] + (["ransomware"] if ex.get("ransomware") else []) + [x for x in tags if x in ("rce", "critical-infra")]
    elif t == "ransomware":
        sev = "medium"
        sector = (ex.get("sector") or "").lower()
        tags = ["ransomware"] + [v for k, v in SECTOR_TAGS.items() if k in sector][:1]
    elif t == "breach" and it["source_id"] == "hibp":
        n = ex.get("accounts") or 0
        sev = "low" if ex.get("spam_list") else "critical" if n >= 10_000_000 else "high" if n >= 1_000_000 else "medium"
        tags = ["breach"]
    elif t == "breach":
        sev = sev_from_score(score + 1)
        tags = uniq(["breach"] + tags)
    elif t == "supply-chain":
        sev, tags = "critical", uniq(["supply-chain", "malware"] + tags)
    elif t == "vuln":
        sev = "medium"
        pkgs = [p.split("/", 1)[-1].lower() for p in ex.get("packages", [])]
        if any(c in ctx["kev_cves"] for c in it.get("cves", [])):
            sev = "critical"
        elif any(len(p) >= 4 and mentioned(p, ctx["news_text"]) for p in pkgs):
            sev = "high"
        tags = uniq(["vuln"] + [x for x in tags if x in ("rce", "ai", "cloud", "identity")])
    elif t == "advisory":
        url, title = it.get("url", "").lower(), it["title"].lower()
        sev = sev_from_score(score)
        if re.search(r"adds? .{0,40}known exploited vulnerabilit", title):
            sev = "low"  # the KEV entries themselves are already on the board
        elif "/ics-advisories/" in url or "/ics-medical-advisories/" in url or title.startswith("icsa"):
            sev = "medium" if score >= 4 else "low"
        elif "/cybersecurity-advisories/aa" in url or "joint" in title or "#stopransomware" in title:
            sev = SEVERITIES[max(SEV_RANK[sev], SEV_RANK["high"])]
    elif t == "community":
        sev = bump(sev_from_score(score), -1)
        if (ex.get("points") or 0) >= 300 and sev != "low":
            sev = bump(sev, 1)
    else:
        sev = sev_from_score(score)
    it["severity"] = sev
    it["tags"] = uniq(tags)[:6]


def mentioned(term: str, haystack: str) -> bool:
    return re.search(r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])", haystack) is not None


# ---------------------------------------------------------------- sources

def make_item(src: dict, type_: str, title: str, url: str, published: datetime, summary: str = "",
              extra: dict | None = None, cves: list | None = None, uid: str | None = None) -> dict:
    link = strip_tracking(url)
    title = clean(title, 220)
    summary = clean(summary, 320)
    key = uid or (canon_url(link) if link else f"{src['id']}:{title}")
    found = sorted({c.upper() for c in CVE_RE.findall(f"{title} {summary}")} | set(cves or []))
    return {
        "id": hashlib.sha1(key.encode("utf-8")).hexdigest()[:12],
        "type": type_, "title": title, "url": link, "source": src["name"], "source_id": src["id"],
        "published": iso(published), "summary": summary, "cves": found[:8], "extra": extra or {},
    }


def ad_rss(src, ctx):
    raw = fetch(src["url"], "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5")
    entries = parse_feed(raw)
    if not entries and re.search(rb"<html[\s>]", raw[:2000], re.I):
        raise RuntimeError("the feed URL now returns a web page instead of RSS; the feed may have moved")
    items = []
    for e in entries[: src.get("max_items", 60)]:
        if e["title"] and e["link"]:
            items.append(make_item(src, src.get("type", "news"), e["title"], e["link"],
                                   parse_date(e["date"]) or ctx["now"], e["summary"]))
    return items, []


def ad_kev(src, ctx):
    try:
        data = fetch_json(src["url"])
    except Exception:
        if not src.get("fallback_url"):
            raise
        data = fetch_json(src["fallback_url"])
    vulns = data.get("vulnerabilities", [])
    ctx["kev_cves"] = {v.get("cveID", "") for v in vulns}
    ctx["vocab"].update(tok.lower() for v in vulns
                        for tok in re.findall(r"[A-Za-z][A-Za-z0-9.+\-]{2,}", f"{v.get('vendorProject', '')} {v.get('product', '')}")
                        if tok.lower() not in STOP)
    cutoff = ctx["now"] - timedelta(days=WINDOW_DAYS)
    items = []
    for v in vulns:
        added = parse_iso(v.get("dateAdded", ""))
        if not added or added < cutoff:
            continue
        cve = v["cveID"]
        name = v.get("vulnerabilityName") or f"{v.get('vendorProject')} {v.get('product')} vulnerability"
        extra = {"vendor": v.get("vendorProject", ""), "product": v.get("product", ""), "due": v.get("dueDate", ""),
                 "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                 "action": clean(v.get("requiredAction", ""), 220), "date_only": True}
        items.append(make_item(src, "kev", f"{cve}: {name}", f"https://nvd.nist.gov/vuln/detail/{cve}", added,
                               v.get("shortDescription", ""), extra, [cve], uid=f"kev:{cve}"))
    return items, []


def ad_ransomware_live(src, ctx):
    data = fetch_json(src["url"])
    items = []
    for v in data if isinstance(data, list) else data.get("victims", []):
        victim, group = (v.get("victim") or "").strip(), (v.get("group") or "").strip()
        if not victim or not group:
            continue
        group_page = "https://www.ransomware.live/group/" + urllib.parse.quote(group)
        url = v.get("url") if str(v.get("url") or "").startswith("https://") else group_page
        sector = "" if (v.get("activity") or "").lower() in ("", "not found", "unknown") else v["activity"]
        country = v.get("country") or ""
        lead = " · ".join(b for b in (sector, country) if b)
        desc = clean(v.get("description") or "", 200)
        extra = {"group": group, "victim": victim, "country": country, "sector": sector, "domain": v.get("domain") or ""}
        items.append(make_item(src, "ransomware", f"{group} claims {victim}", url,
                               parse_iso(v.get("discovered") or v.get("attackdate") or "") or ctx["now"],
                               f"{lead} — {desc}" if lead and desc else lead or desc, extra,
                               uid=f"rw:{norm(group)}:{norm(victim)}"))
    return items, []


def ad_ransomlook(src, ctx):
    data = fetch_json(src["url"])
    items = []
    for v in data if isinstance(data, list) else []:
        victim, group = (v.get("post_title") or "").strip(), (v.get("group_name") or "").strip()
        if not victim or not group:
            continue
        desc = clean(v.get("description") or "", 200)
        desc = "" if desc.lower() in ("none", "null") else desc
        items.append(make_item(src, "ransomware", f"{group} claims {victim}",
                               "https://www.ransomlook.io/group/" + urllib.parse.quote(group),
                               parse_iso(v.get("discovered") or "") or ctx["now"], desc,
                               {"group": group, "victim": victim, "country": "", "sector": ""},
                               uid=f"rw:{norm(group)}:{norm(victim)}"))
    return items, []


def ad_ransomware_live_attacks(src, ctx):
    data = fetch_json(src["url"])
    cutoff = ctx["now"] - timedelta(days=WINDOW_DAYS)
    items = []
    for v in data if isinstance(data, list) else []:
        added = parse_iso(v.get("added") or v.get("date") or "")
        victim = (v.get("victim") or "").strip()
        url = v.get("url") or v.get("link") or ""
        if not added or added < cutoff or not victim or not url.startswith("http"):
            continue
        title = v.get("title") or f"{victim} discloses a cyberattack"
        extra = {"victim": victim, "country": v.get("country") or "", "attack_date": v.get("date") or "",
                 "gang": v.get("claim_gang") or "", "date_only": True}
        items.append(make_item(src, "breach", title, url, added, v.get("summary") or v.get("description") or "",
                               extra, uid=f"atk:{norm(victim)}:{v.get('date') or ''}"))
    return items, []


def ad_hibp(src, ctx):
    data = fetch_json(src["url"])
    cutoff = ctx["now"] - timedelta(days=WINDOW_DAYS)
    items = []
    for b in data:
        added = parse_iso(b.get("AddedDate", ""))
        if not added or added < cutoff or b.get("IsFabricated") or b.get("IsRetired"):
            continue
        n = int(b.get("PwnCount") or 0)
        name = b.get("Title") or b.get("Name")
        extra = {"accounts": n, "data_classes": (b.get("DataClasses") or [])[:8], "breach_date": b.get("BreachDate", ""),
                 "domain": b.get("Domain", ""), "spam_list": bool(b.get("IsSpamList")), "victim": name}
        items.append(make_item(src, "breach", f"{name}: {n:,} accounts added to Have I Been Pwned",
                               "https://haveibeenpwned.com/Breach/" + urllib.parse.quote(b["Name"]), added,
                               b.get("Description", ""), extra, uid=f"hibp:{b['Name']}"))
    return items, []


def ad_github_malware(src, ctx):
    data = fetch_json(src["url"])
    packages = []
    for a in data:
        for v in a.get("vulnerabilities") or []:
            p = v.get("package") or {}
            if p.get("name"):
                packages.append({"ghsa": a["ghsa_id"], "ecosystem": p.get("ecosystem", ""), "name": p["name"],
                                 "versions": v.get("vulnerable_version_range") or "",
                                 "published": a.get("published_at", ""), "url": a.get("html_url", ""),
                                 "summary": clean(a.get("summary", ""), 140)})
    return [], packages


def ad_github_advisories(src, ctx):
    data = fetch_json(src["url"])
    items = []
    for a in data:
        pkgs = [(v["package"].get("ecosystem", ""), v["package"].get("name", ""))
                for v in a.get("vulnerabilities") or [] if v.get("package")]
        title = a.get("summary") or a["ghsa_id"]
        if pkgs and pkgs[0][1].lower() not in title.lower():
            title = f"{pkgs[0][1]} ({pkgs[0][0]}): {title}"
        fixed = [v.get("first_patched_version") for v in a.get("vulnerabilities") or [] if v.get("first_patched_version")]
        cvss = (a.get("cvss") or {}).get("score") or ((a.get("cvss_severities") or {}).get("cvss_v4") or {}).get("score")
        extra = {"packages": [f"{e}/{n}" for e, n in pkgs][:5], "fixed": [str(f) for f in fixed][:3],
                 "cvss": cvss, "ghsa": a["ghsa_id"]}
        items.append(make_item(src, "vuln", title, a.get("html_url", ""), parse_iso(a.get("published_at", "")) or ctx["now"],
                               a.get("description", ""), extra, [a["cve_id"]] if a.get("cve_id") else [],
                               uid=f"ghsa:{a['ghsa_id']}"))
    return items, []


HN_RELEVANT = _rx(r"breach|hacked|hackers?\b|ransomware|zero[- ]?day|0[- ]?day|exploit|vulnerab|cve-\d|compromis|malware|backdoor|leak|stolen|supply[- ]chain|phishing|spyware|botnet|ddos|infostealer|\bworm\b|\brce\b|cyberattack|security incident|credential")
HN_NOISE = _rx(r"hacked together|^show hn|^ask hn|^tell hn|life ?hack|growth hack|hackathon|hacker news|hackers? (?:guide|handbook|delight)")


def ad_hn(src, ctx):
    since = int((ctx["now"] - timedelta(days=7)).timestamp())
    hits, failures = {}, 0
    for q in src.get("queries", []):
        url = "https://hn.algolia.com/api/v1/search_by_date?" + urllib.parse.urlencode({
            "query": q, "tags": "story", "hitsPerPage": 30,
            "numericFilters": f"points>{src.get('min_points', 40)},created_at_i>{since}"})
        try:
            data = fetch_json(url)
        except Exception:
            failures += 1
            continue
        for h in data.get("hits", []):
            title = h.get("title") or ""
            if HN_RELEVANT.search(title) and not HN_NOISE.search(title):
                hits.setdefault(h["objectID"], h)
    if failures and failures == len(src.get("queries", [])):
        raise RuntimeError("every Hacker News query failed")
    items = []
    for h in hits.values():
        hn_url = f"https://news.ycombinator.com/item?id={h['objectID']}"
        extra = {"points": h.get("points") or 0, "comments": h.get("num_comments") or 0, "hn_url": hn_url}
        items.append(make_item(src, "community", h["title"], h.get("url") or hn_url,
                               parse_iso(h.get("created_at", "")) or ctx["now"],
                               f"{extra['points']} points · {extra['comments']} comments on Hacker News", extra,
                               uid=f"hn:{h['objectID']}"))
    return items, []


ADAPTERS = {
    "rss": ad_rss, "cisa_kev": ad_kev, "ransomware_live": ad_ransomware_live, "ransomlook": ad_ransomlook,
    "ransomware_live_attacks": ad_ransomware_live_attacks, "hibp": ad_hibp, "github_malware": ad_github_malware,
    "github_advisories": ad_github_advisories, "hn": ad_hn,
}


def sweep(sources: list[dict], ctx: dict):
    def run(src):
        t0 = time.time()
        try:
            items, packages = ADAPTERS[src["kind"]](src, ctx)
            return src, items, packages, None, time.time() - t0
        except Exception as e:
            return src, [], [], f"{type(e).__name__}: {e}"[:200], time.time() - t0

    fetched, packages, status = [], [], []
    with ThreadPoolExecutor(max_workers=10) as pool:
        for src, items, pkgs, err, secs in pool.map(run, sources):
            fetched += items
            packages += pkgs
            status.append({"id": src["id"], "name": src["name"], "kind": src["kind"], "type": src.get("type", "news"),
                           "home": src.get("home", ""), "ok": err is None, "count": len(items) + len(pkgs),
                           "error": err, "fetched_at": iso(ctx["now"]), "ms": int(secs * 1000)})
    return fetched, packages, status


# ---------------------------------------------------------------- merging history

def merge_items(previous: list[dict], fetched: list[dict], now: datetime) -> list[dict]:
    by_id: dict[str, dict] = {it["id"]: it for it in previous}
    fresh: set[str] = set()
    for it in fetched:
        old = by_id.get(it["id"])
        if old and it["id"] in fresh and old["source_id"] != it["source_id"]:
            also = old["extra"].setdefault("also", [])
            if it["source"] not in also:
                also.append(it["source"])  # the same incident from a second tracker
            continue
        if old:
            it["first_seen"] = old.get("first_seen")
            if old["source_id"] != it["source_id"]:  # keep whichever tracker reported it first
                also = old["extra"].setdefault("also", [])
                if it["source"] not in also:
                    also.append(it["source"])
                fresh.add(it["id"])
                continue
            if old["extra"].get("also"):
                it["extra"]["also"] = old["extra"]["also"]
            if old["extra"].get("hn"):
                it["extra"]["hn"] = old["extra"]["hn"]
        by_id[it["id"]] = it
        fresh.add(it["id"])

    # A Hacker News thread about a story we already carry becomes a note on that story.
    by_url = {canon_url(it["url"]): it for it in by_id.values() if it["type"] != "community" and it["url"]}
    for it in list(by_id.values()):
        if it["type"] == "community" and it["url"]:
            twin = by_url.get(canon_url(it["url"]))
            if twin:
                twin["extra"]["hn"] = {k: it["extra"].get(k) for k in ("points", "comments", "hn_url")}
                del by_id[it["id"]]

    cutoff = now - timedelta(days=WINDOW_DAYS)
    out = []
    for it in by_id.values():
        dt = parse_iso(it["published"])
        if not dt or dt < cutoff:
            continue
        if dt > now + timedelta(hours=1):
            it["published"] = iso(now)  # feeds with broken time zones
        out.append(it)
    out.sort(key=lambda it: it["published"], reverse=True)
    return out


def merge_packages(previous: list[dict], fetched: list[dict], now: datetime) -> list[dict]:
    by_key: dict[str, dict] = {}
    for p in previous + fetched:
        key = f"{p['ecosystem']}/{p['name']}".lower()
        old = by_key.get(key)
        if old:
            old["versions"] = ", ".join(uniq([*old["versions"].split(", "), *p["versions"].split(", ")]))[:120]
            old["published"] = max(old["published"], p["published"])
        else:
            by_key[key] = dict(p)
    cutoff = iso(now - timedelta(days=PACKAGE_DAYS))
    return sorted((p for p in by_key.values() if p["published"] >= cutoff), key=lambda p: p["published"], reverse=True)


# ---------------------------------------------------------------- developing situations

STOP = set("""
a about above across after again against ago all almost along already also although always am amid among an and another any
are around as at away back be because become been before being below between beyond both but by can cannot could did do does
doing done down during each either else enough even ever every few for from further get gets getting give given gives go goes
going gone got had has have having he her here hers him his how however if in inside into is it its itself just keep keeps
last later least less let like likely made make makes making many may maybe me might more most much must my near nearly need
needs never new next no nor not now of off often on once one only onto or other others our out over own part per perhaps
please put rather really said same say says see seen set several shall she should show shows since so some soon still such
take takes taken than that the their them then there these they thing things this those though through thus to today told
too took toward under until up upon us use used uses using very via want was way we well were what when where whether which
while who whom whose why will with within without would yet you your
first second third two three four five six seven eight nine ten hundreds thousands dozens million millions billion billions
january february march april may june july august september october november december monday tuesday wednesday thursday
friday saturday sunday week weeks weekly month months year years day days daily hour hours minute minutes time times
new news update updates updated report reports reported reporting reveals revealed warns warn warning warnings alert alerts
says said claims claimed confirms confirmed confirm discloses disclosed disclosure announces announced launch launches
patch patches patched patching fix fixes fixed fixing flaw flaws bug bugs vulnerability vulnerabilities vuln vulns issue issues
exploit exploits exploited exploiting exploitation attack attacks attacked attacker attackers hacker hackers hack hacked hacking
breach breaches breached data security cyber cybersecurity cyberattack cyberattacks threat threats actor actors group groups
gang gangs campaign campaigns malware ransomware zero-day zero-days zeroday critical high severe major serious huge massive
users user customers customer company companies firm firms government agency agencies researchers research researcher
expert experts official officials team teams people today latest top how why what when who where which more most still now
inc ltd llc corp corporation co group cve cves cisa fbi nsa ncsc doj sec ftc us u.s. uk eu ai api apis ceo cto ciso it
attempts attempt access accessed stolen stole steal steals leak leaked leaks leaking exposed exposes exposure expose risk risks
risky emergency urgent urgently remote code execution remotely execute executes arbitrary allows allow allowing lets could
affected affects affect affecting impacted impact impacts targeting targeted targets target hit hits hitting new-found
online internet web website websites app apps application applications software service services system systems network
networks server servers device devices platform platforms tool tools product products account accounts information info
personal sensitive private public global world worldwide national federal state states local international american
chinese russian iranian north korean european british largest biggest big small first-ever ever behind inside sources
source open free paid help support supports watch read here this that latest breaking exclusive analysis explained
potential possible possibly probably alleged allegedly suspected suspect suspects linked tied ties link links back-to
""".split())
BROAD_NAMES = set("microsoft google apple amazon aws meta windows linux android chrome ios macos".split())
WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+\-]*[A-Za-z0-9+]|[A-Za-z0-9]")


def is_title_case(title: str) -> bool:
    words = [w for w in re.findall(r"[A-Za-z][A-Za-z'\-]+", title) if len(w) > 3]
    return len(words) >= 3 and sum(w[0].isupper() for w in words) / len(words) >= 0.7


def title_tokens(title: str, vocab: set, sentence_names: set | None) -> list[tuple[int, str]]:
    """Proper-noun-ish tokens with their word positions.

    Capital letters only mean something in sentence-case headlines; in Title
    Case headlines a token counts only if it is a known vendor or product,
    looks like a name (LiteLLM, PHP2Shell, NetScaler), or shows up capitalised
    in some sentence-case headline (sentence_names).
    """
    tc = is_title_case(title)
    out = []
    for i, w in enumerate(WORD_RE.findall(title.replace("’", "'"))):
        w = re.sub(r"'s$", "", w)
        lw = w.lower()
        if len(w) < 3 or lw in STOP or w.isdigit() or CVE_RE.fullmatch(w):
            continue
        special = bool(re.search(r"[a-z][A-Z]|[A-Z]{2,}|[A-Za-z]\d|\d[A-Za-z]", w))
        if not (w[0].isupper() or special):
            continue
        known = special or lw in vocab or (sentence_names is not None and lw in sentence_names)
        if tc and not known:
            continue
        if not tc and i == 0 and not known:
            continue  # the first word of a sentence is capitalised anyway
        out.append((i, w))
    return out


def find_situations(items: list[dict], ctx: dict) -> list[dict]:
    now, vocab = ctx["now"], ctx["vocab"]
    recent = [it for it in items if it["type"] not in ("ransomware", "vuln")
              and it["severity"] != "low" and hours_since(it["published"], now) <= 72]
    sentence_names = {w.lower() for it in recent if not is_title_case(it["title"])
                      for _, w in title_tokens(it["title"], vocab, None)}
    by_id = {it["id"]: it for it in recent}
    index: dict[str, set] = {}
    forms: dict[str, Counter] = {}
    toks_by_id: dict[str, list] = {}
    for it in recent:
        toks = title_tokens(it["title"], vocab, sentence_names)
        toks_by_id[it["id"]] = toks
        keys = set(it.get("cves", []))
        for _, w in toks:
            keys.add(w.lower())
            forms.setdefault(w.lower(), Counter())[w] += 1
        for k in keys:
            index.setdefault(k, set()).add(it["id"])

    candidates = []
    for key, ids in index.items():
        if key in BROAD_NAMES:
            continue  # too broad to be a story on its own; still used in names like "Microsoft SharePoint"
        srcs = {by_id[i]["source"] for i in ids}
        has_kev = any(by_id[i]["type"] == "kev" for i in ids)
        if len(srcs) >= 3 or (len(srcs) >= 2 and has_kev):
            candidates.append((key, ids, srcs))
    candidates.sort(key=lambda c: (-len(c[2]), -len(c[1]), c[0]))

    # Union-find: keys that mostly share reports, or name each other ("php" / "php2shell"), are one story.
    parent = list(range(len(candidates)))

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for a in range(len(candidates)):
        for b in range(a + 1, len(candidates)):
            ka, ia, _ = candidates[a]
            kb, ib, _ = candidates[b]
            nested = len(ka) >= 3 and len(kb) >= 3 and not ka.startswith("cve-") and not kb.startswith("cve-") \
                and (ka in kb or kb in ka) and ia & ib
            if nested or len(ia & ib) / min(len(ia), len(ib)) >= 0.5:
                parent[root(b)] = root(a)
    merged: dict[int, dict] = {}
    for i, (key, ids, _) in enumerate(candidates):
        g = merged.setdefault(root(i), {"keys": [], "ids": set()})
        g["keys"].append(key)
        g["ids"] |= ids
    groups = list(merged.values())

    out = []
    for g in groups:
        members = sorted((by_id[i] for i in g["ids"]),
                         key=lambda m: (SEV_RANK[m["severity"]], m["published"]), reverse=True)
        srcs = uniq(m["source"] for m in members)
        top = max(SEV_RANK[m["severity"]] for m in members)
        if len(srcs) < 2 or top < SEV_RANK["high"]:
            continue
        if len(srcs) >= 8:
            top = SEV_RANK["critical"]  # a story this many outlets are on is big by definition
        name = situation_name(g["keys"], members, toks_by_id, forms, index)
        lead = next((m for m in members if m["type"] in ("news", "advisory", "breach")), members[0])
        weight = sum(SEV_WEIGHT[m["severity"]] for m in members) * (1 + 0.15 * len(srcs))
        out.append({
            "id": hashlib.sha1(name.lower().encode()).hexdigest()[:10], "name": name,
            "severity": SEVERITIES[top], "source_count": len(srcs), "sources": srcs[:8], "count": len(members),
            "cves": sorted({c for m in members for c in m.get("cves", [])})[:6], "items": [m["id"] for m in members],
            "first": min(m["published"] for m in members), "last": max(m["published"] for m in members),
            "lead": {k: lead[k] for k in ("title", "url", "source", "published")},
            "tags": [t for t, _ in Counter(t for m in members for t in m.get("tags", [])).most_common(4)],
            "weight": round(weight, 1),
        })
    out.sort(key=lambda s: -s["weight"])
    return out[:8]


def situation_name(keys: list[str], members: list[dict], toks_by_id: dict, forms: dict, index: dict) -> str:
    # A named bug that contains the product's name ("PHP2Shell" for "PHP") is what people call the story.
    words = sorted((k for k in keys if not k.startswith("cve-") and k in forms), key=lambda k: -len(index.get(k, ())))
    if words:
        top = words[0]
        for k in words[1:]:
            if top in k and len(index.get(k, ())) >= 0.4 * len(index.get(top, ())):
                return forms[k].most_common(1)[0][0]
    keyset = set(keys)
    phrases: Counter = Counter()
    for m in members:
        toks = toks_by_id.get(m["id"], [])
        seen_here = set()
        for n in (3, 2):
            for j in range(len(toks) - n + 1):
                run = toks[j:j + n]
                if run[-1][0] - run[0][0] != n - 1:
                    continue  # not adjacent in the headline
                if any(w.lower() in keyset for _, w in run):
                    seen_here.add(" ".join(w for _, w in run))
        phrases.update(seen_here)
    best = sorted(((c, len(p.split()), p) for p, c in phrases.items() if c >= 2), reverse=True)
    if best:
        return best[0][2]
    for k in keys:
        if not k.upper().startswith("CVE-"):
            return forms[k].most_common(1)[0][0] if k in forms else k
    return keys[0].upper()


# ---------------------------------------------------------------- the picture

def compute_level(items: list[dict], situations: list[dict], now: datetime, thresholds: list) -> dict:
    heat, ransom, crit48, kev72 = 0.0, 0.0, 0, 0
    for it in items:
        age = hours_since(it["published"], now)
        if it["type"] == "kev":
            if age <= 72:
                heat += 4
                kev72 += 1
            continue
        if age > 48:
            continue
        if it["type"] == "ransomware":
            ransom += 0.25
            continue
        heat += SEV_WEIGHT[it["severity"]]
        crit48 += it["severity"] == "critical"
    heat += min(ransom, 20)
    heat += sum(5 for s in situations if s["source_count"] >= 5)
    value = 5
    for lv, th in zip((4, 3, 2, 1), thresholds):
        if heat >= th:
            value = lv
    bits = []
    if kev72:
        bits.append(f"{kev72} exploited vulnerabilit{'y' if kev72 == 1 else 'ies'} added to CISA KEV in 72 hours")
    if crit48:
        bits.append(f"{crit48} critical report{'s' if crit48 != 1 else ''} in 48 hours")
    if situations:
        bits.append(f"top story: {situations[0]['name']} ({situations[0]['source_count']} outlets)")
    name, blurb = LEVELS[value]
    reason = "; ".join(bits)
    return {"value": value, "name": name, "blurb": blurb, "heat": round(heat, 1),
            "reason": reason[:1].upper() + reason[1:] + "." if bits else "Nothing notable in the last 48 hours."}


def build_stats(items: list[dict], packages: list[dict], status: list[dict], now: datetime, first_sweep: str) -> dict:
    def within(it, h):
        return hours_since(it["published"], now) <= h

    reports = [it for it in items if it["type"] != "ransomware"]
    claims = [it for it in items if it["type"] == "ransomware"]
    groups: dict[str, dict] = {}
    for it in claims:
        if within(it, 168):
            g = it["extra"].get("group") or "unknown"
            row = groups.setdefault(g.lower(), {"group": g, "count": 0, "count_24h": 0})
            row["count"] += 1
            row["count_24h"] += within(it, 24)
    # Feeds keep a few days of backlog, so the days just before the first sweep are covered too.
    first_day = ((parse_iso(first_sweep) or now) - timedelta(days=3)).date()
    daily = []
    for back in range(WINDOW_DAYS - 1, -1, -1):
        day = (now - timedelta(days=back)).date()
        row = {"date": day.isoformat(), "critical": 0, "high": 0, "medium": 0, "partial": day < first_day}
        daily.append(row)
    by_day = {row["date"]: row for row in daily}
    for it in reports:
        row = by_day.get(it["published"][:10])
        if row and it["severity"] in ("critical", "high", "medium"):
            row[it["severity"]] += 1
    return {
        "stats": {
            "reports_24h": sum(within(it, 24) for it in reports),
            "critical_24h": sum(within(it, 24) and it["severity"] == "critical" for it in reports),
            "high_24h": sum(within(it, 24) and it["severity"] == "high" for it in reports),
            "kev_7d": sum(it["type"] == "kev" and within(it, 168) for it in items),
            "kev_ransomware_7d": sum(it["type"] == "kev" and within(it, 168) and it["extra"].get("ransomware") for it in items),
            "ransomware_24h": sum(within(it, 24) for it in claims),
            "ransomware_7d": sum(within(it, 168) for it in claims),
            "breaches_7d": sum(it["type"] == "breach" and within(it, 168) for it in items),
            "packages_72h": sum(hours_since(p["published"], now) <= 72 for p in packages),
            "packages_ecosystems": dict(Counter(p["ecosystem"] for p in packages if hours_since(p["published"], now) <= 72)),
            "sources_ok": sum(s["ok"] for s in status),
            "sources_total": len(status),
        },
        "daily": daily,
        "ransomware": {"groups_7d": sorted(groups.values(), key=lambda r: (-r["count"], r["group"].lower()))[:10]},
    }


GENERIC_PACKAGE_NAMES = set("""test demo core utils util common sdk api app node python react client server config
index main http https request requests crypto security update install setup build tools tool cli helper helpers
logger auth token login wallet bot proxy""".split())


def promote_packages(packages: list[dict], ctx: dict) -> list[dict]:
    """A malicious release of a package the news is talking about goes on the main board."""
    src = {"id": "github-malware", "name": "GitHub Advisory DB (malware)"}
    out = []
    for p in packages:
        name = p["name"].lower()
        p["in_news"] = len(name) >= 4 and name not in GENERIC_PACKAGE_NAMES and mentioned(name, ctx["news_text"])
        if p["in_news"]:
            it = make_item(src, "supply-chain", f"Malicious {p['ecosystem']} release: {p['name']} {p['versions']}".strip(),
                           p["url"], parse_iso(p["published"]) or ctx["now"],
                           f"{p['summary']} Flagged in the GitHub Advisory Database and named in this week's coverage.",
                           {"packages": [f"{p['ecosystem']}/{p['name']}"], "versions": p["versions"]}, uid=f"pkg:{p['ghsa']}")
            it["first_seen"] = ctx["seen"].get(it["id"])
            out.append(it)
    return out


def load_sitrep() -> dict | None:
    # The scheduled analyst writes state/sitrep.json and commits a copy as sitrep.json at the
    # repository root, so the GitHub deploy can show it too. Whichever is newer wins.
    found = [load_json(STATE / "sitrep.json", None), load_json(ROOT / "sitrep.json", None)]
    found = [f for f in found if isinstance(f, dict) and f.get("headline")]
    if not found:
        return None
    raw = max(found, key=lambda f: str(f.get("written_at") or ""))
    if hours_since(str(raw.get("written_at") or ""), now_utc()) > 36:
        return None  # stale analysis is worse than none

    def safe_url(u):
        return u if isinstance(u, str) and u.startswith("https://") else ""

    bullets = []
    for b in raw.get("bullets", [])[:6]:
        if isinstance(b, str):
            b = {"text": b}
        if isinstance(b, dict) and b.get("text"):
            bullets.append({"text": clean(b["text"], 360), "url": safe_url(b.get("url"))})
    return {"written_at": raw.get("written_at") or "", "by": clean(raw.get("by") or "Claude", 40),
            "headline": clean(raw["headline"], 160), "bullets": bullets,
            "actions": [clean(a, 200) for a in raw.get("actions", [])[:6] if isinstance(a, str) and a.strip()]}


def load_prompt_parts() -> dict:
    text = (ROOT / "MASTER_PROMPT.md").read_text(encoding="utf-8")
    parts, current = {}, None
    for line in text.splitlines(keepends=True):
        m = re.match(r"^<!--\s*([a-z:-]+)\s*-->\s*$", line)
        if m:
            current = m.group(1)
            parts[current] = ""
        elif current:
            parts[current] += line
    parts = {k: v.strip() for k, v in parts.items()}
    return {"template": parts.get("prompt", ""),
            "run_mode": {"code": parts.get("run-mode:code", ""), "chat": parts.get("run-mode:chat", "")},
            "alerts": {"feed": parts.get("alerts:feed", ""), "nofeed": parts.get("alerts:nofeed", "")}}


def make_brief(data: dict, now: datetime) -> str:
    lv, items = data["level"], data["items"]
    lines = [f"SITCON {lv['value']} of 5 ({lv['name']}): {lv['blurb']} {lv['reason']}"]
    sr = data.get("sitrep")
    if sr:
        lines += ["", f"Analyst summary ({sr['written_at']}): {sr['headline']}"]
        lines += [f"- {b['text']}" + (f" ({b['url']})" if b.get("url") else "") for b in sr["bullets"]]
    if data["situations"]:
        lines += ["", "Developing situations (three or more outlets in the last 72 hours):"]
        for s in data["situations"]:
            cves = f"; {', '.join(s['cves'])}" if s["cves"] else ""
            ld = s["lead"]
            lines.append(f"- {s['name']}: {s['source_count']} outlets, worst severity {s['severity']}{cves}. "
                         f"Lead report: \"{ld['title']}\" ({ld['source']}, {ld['published'][:10]}) {ld['url']}")
    hot = [it for it in items if it["severity"] in ("critical", "high") and it["type"] not in ("ransomware", "kev")
           and hours_since(it["published"], now) <= 168][:25]
    if hot:
        lines += ["", "Critical and high-severity reports, last 7 days, newest first:"]
        for it in hot:
            extra = [c for c in it["cves"] if c not in it["title"]]
            lines.append(f"- [{it['severity']}] {it['published'][:10]} {it['title']} ({it['source']}) {it['url']}"
                         + (f" [{', '.join(extra)}]" if extra else ""))
    kev = [it for it in items if it["type"] == "kev"][:25]
    if kev:
        lines += ["", "Added to CISA's Known Exploited Vulnerabilities catalog, last 14 days:"]
        for it in kev:
            ex = it["extra"]
            lines.append(f"- {it['cves'][0]}: {ex['vendor']} {ex['product']}. {it['title'].split(': ', 1)[-1]}. "
                         f"Added {it['published'][:10]}, federal due date {ex['due']}, "
                         f"known ransomware use: {'yes' if ex.get('ransomware') else 'unknown'}.")
    pk = data["packages"]
    if pk:
        lines += ["", f"Malicious packages in the GitHub Advisory Database, last {PACKAGE_DAYS} days "
                      f"({len(pk)} listed; newest 40 shown; any named in the news come first):"]
        newest = sorted(pk, key=lambda p: p["published"], reverse=True)
        for p in sorted(newest, key=lambda p: not p.get("in_news"))[:40]:
            lines.append(f"- {p['ecosystem']}/{p['name']} {p['versions']}".rstrip() + (" (in the news)" if p.get("in_news") else ""))
    groups = data["ransomware"]["groups_7d"][:8]
    if groups:
        lines += ["", "Most active ransomware groups by leak-site claims, last 7 days: "
                  + ", ".join(f"{g['group']} ({g['count']})" for g in groups) + "."]
    breaches = [it for it in items if it["type"] == "breach" or (it["type"] == "news" and "breach" in it["tags"] and it["severity"] != "low")][:14]
    if breaches:
        lines += ["", "Recently disclosed breaches:"]
        lines += [f"- {it['published'][:10]} {it['title']} ({it['source']}) {it['url']}" for it in breaches]
    return "\n".join(lines)


def build(items: list[dict], packages: list[dict], status: list[dict], cfg: dict, now: datetime, meta: dict) -> dict:
    news_text = " ".join(f"{it['title']} {it['summary']}" for it in items
                         if it["type"] in ("news", "advisory", "community", "breach")).lower()
    ctx = {"now": now, "news_text": news_text, "vocab": set(meta.get("vocab", [])),
           "kev_cves": set(meta.get("kev_cves", [])), "seen": meta.get("seen", {})}
    for it in items:
        rescore(it, ctx)
    items = sorted(items + promote_packages(packages, ctx), key=lambda it: it["published"], reverse=True)
    situations = find_situations(items, ctx)
    level = compute_level(items, situations, now, cfg.get("level_thresholds") or DEFAULT_THRESHOLDS)
    prev = meta.get("level") or {}
    level["changed_from"] = prev.get("value") if prev.get("value") not in (None, level["value"]) else None
    level["since"] = prev.get("since") if prev.get("value") == level["value"] else iso(now)
    site_url = (os.environ.get("SM_SITE_URL") or cfg.get("site_url") or "").strip()
    if site_url and not site_url.endswith("/"):
        site_url += "/"
    data = {
        "schema": 1, "name": "The Situation Monitor", "generated_at": iso(now),
        "first_sweep_at": meta.get("first_sweep_at") or iso(now), "window_days": WINDOW_DAYS,
        "schedule_note": os.environ.get("SM_SCHEDULE_NOTE") or cfg.get("schedule_note") or "",
        "site_url": site_url, "feed_url": site_url + "data/feed.xml" if site_url else "",
        "repo_url": (os.environ.get("SM_REPO_URL") or cfg.get("repo_url") or "").strip(),
        "level": level, "levels": {str(k): {"name": v[0], "blurb": v[1]} for k, v in LEVELS.items()},
        "situations": situations, "sitrep": load_sitrep(), "items": items, "packages": packages[:300],
        "sources": status,
    }
    data.update(build_stats(items, packages, status, now, data["first_sweep_at"]))
    data["prompt"] = load_prompt_parts()
    data["prompt_brief"] = make_brief(data, now)
    for it in data["items"]:
        it.setdefault("first_seen", None)
    return data


# ---------------------------------------------------------------- outputs

def trim_item(it: dict, summary_len: int) -> dict:
    out = {k: v for k, v in it.items() if k != "extra"}
    out["summary"] = clean(it.get("summary", ""), summary_len)
    ex = dict(it.get("extra") or {})
    ex.pop("domain", None)
    if "data_classes" in ex:
        ex["data_classes"] = ex["data_classes"][:4]
    out["extra"] = ex
    return out


def compact_for_store(data: dict) -> dict:
    """The live-store copy: the same shape, cut down to fit one 256 KiB document."""
    live = data
    for hi, med, rw, pk, slen in ((170, 130, 70, 60, 220), (140, 100, 50, 50, 180), (110, 80, 40, 40, 150),
                                  (80, 50, 30, 30, 120), (50, 30, 20, 20, 90)):
        items = data["items"]
        keep = {it["id"] for it in [i for i in items if i["severity"] in ("critical", "high")][:hi]}
        keep |= {it["id"] for it in [i for i in items if i["severity"] == "medium" and i["type"] != "ransomware"][:med]}
        keep |= {it["id"] for it in [i for i in items if i["type"] == "ransomware"][:rw]}
        live = dict(data, items=[trim_item(it, slen) for it in items if it["id"] in keep],
                    packages=data["packages"][:pk], trimmed_for_store=True)
        if len(json.dumps(live, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= STORE_BUDGET:
            break
    return live


def rss(data: dict) -> str:
    site = data["site_url"] or "https://github.com/"
    rows = []
    for it in [i for i in data["items"] if i["severity"] in ("critical", "high")][:80]:
        dt = parse_iso(it["published"]) or now_utc()
        rows.append(
            "<item>"
            f"<title>{xml_escape('[' + it['severity'].upper() + '] ' + it['title'])}</title>"
            f"<link>{xml_escape(it['url'] or site)}</link>"
            f"<guid isPermaLink=\"false\">situation-monitor-{it['id']}</guid>"
            f"<pubDate>{format_datetime(dt, usegmt=True)}</pubDate>"
            f"<category>{xml_escape(it['type'])}</category>"
            f"<description>{xml_escape(it['source'] + ' — ' + it['summary'])}</description>"
            "</item>")
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rss version=\"2.0\"><channel>"
            "<title>The Situation Monitor: critical and high-severity incidents</title>"
            f"<link>{xml_escape(site)}</link>"
            "<description>Hacks, breaches, exploited vulnerabilities and supply-chain attacks, aggregated from public sources.</description>"
            f"<lastBuildDate>{format_datetime(now_utc(), usegmt=True)}</lastBuildDate>"
            + "".join(rows) + "</channel></rss>\n")


def generic_prompt(data: dict) -> str:
    p = data["prompt"]
    alerts = p["alerts"]["feed"].replace("{{FEED_URL}}", data["feed_url"]) if data["feed_url"] else p["alerts"]["nofeed"]
    fills = {
        "TEAM_NAME": "our team", "RUN_MODE": p["run_mode"]["code"], "GENERATED_AT": data["generated_at"],
        "LEVEL": f"{data['level']['value']} {data['level']['name']}", "SITUATION_BRIEF": data["prompt_brief"],
        "ALERTS_HOOKUP": alerts,
        "TEAM_PROFILE": "(Replace this line with the vendors, products, platforms and packages you rely on. "
                        "The website's \"Protect your team\" builder fills it in for you.)",
    }
    out = p["template"]
    for k, v in fills.items():
        out = out.replace("{{" + k + "}}", v)
    return out + "\n"


APP_WRAPPER = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
               '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
               '<style>:root{color-scheme:light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}'
               'body{margin:0;font:14px/1.4 system-ui,-apple-system,sans-serif}img{max-width:100%}[hidden]{display:none!important}</style>'
               '</head><body>')


def scrub(obj):
    """Drop U+FFFD replacement characters that upstream feeds sometimes carry."""
    if isinstance(obj, str):
        return obj.replace("�", "")
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    return obj


def write_outputs(data: dict, new_items: list[dict], alert_items: list[dict]) -> None:
    data = scrub(data)
    save_json(DATA / "situation.json", data, compact=True)
    save_json(DATA / "live.json", compact_for_store(data), compact=True)
    save_text(DATA / "feed.xml", rss(data))
    save_text(DATA / "master-prompt.md", generic_prompt(data))
    save_json(DATA / "new.json", {"generated_at": data["generated_at"], "count": len(new_items),
                                  "by_severity": dict(Counter(it["severity"] for it in new_items)),
                                  "alerts": [summary_row(it) for it in alert_items],
                                  "items": [summary_row(it) for it in new_items[:100]]})
    app = SITE / "app.html"
    if app.exists():
        save_text(SITE / "index.html", APP_WRAPPER + app.read_text(encoding="utf-8") + "</body></html>\n")


def summary_row(it: dict) -> dict:
    return {k: it.get(k) for k in ("severity", "type", "title", "source", "url", "published")}


# ---------------------------------------------------------------- alerts

def load_config() -> dict:
    cfg = load_json(ROOT / "config.json", {})
    alerts = cfg.setdefault("alerts", {})
    ch = alerts.setdefault("channels", {})
    env = {"slack_webhook": "SM_SLACK_WEBHOOK", "discord_webhook": "SM_DISCORD_WEBHOOK", "teams_webhook": "SM_TEAMS_WEBHOOK",
           "ntfy_topic": "SM_NTFY_TOPIC", "ntfy_server": "SM_NTFY_SERVER", "webhook": "SM_WEBHOOK_URL"}
    for key, var in env.items():
        if os.environ.get(var):
            ch[key] = os.environ[var].strip()
    if os.environ.get("SM_WATCHLIST"):
        alerts["watchlist"] = [w.strip() for w in re.split(r"[,\n;]", os.environ["SM_WATCHLIST"]) if w.strip()]
    if os.environ.get("SM_MIN_SEVERITY") in SEVERITIES:
        alerts["min_severity"] = os.environ["SM_MIN_SEVERITY"]
    return cfg


def watch_hits(it: dict, watchlist: list[str]) -> list[str]:
    ex = it.get("extra") or {}
    hay = " ".join([it["title"], it.get("summary", ""), str(ex.get("vendor", "")), str(ex.get("product", "")),
                    str(ex.get("victim", "")), " ".join(ex.get("packages", []))]).lower()
    return [w for w in watchlist if len(w) >= 2 and mentioned(w, hay)]


def pick_alerts(new_items: list[dict], cfg: dict) -> list[dict]:
    a = cfg.get("alerts", {})
    floor = SEV_RANK.get(a.get("min_severity", "critical"), 3)
    watchlist = a.get("watchlist") or []
    picked = []
    for it in new_items:
        hits = watch_hits(it, watchlist)
        if SEV_RANK[it["severity"]] >= floor or hits:
            picked.append(dict(it, watch=hits))
    picked.sort(key=lambda it: (bool(it["watch"]), SEV_RANK[it["severity"]], it["published"]), reverse=True)
    return picked


def _post(url: str, payload, headers: dict | None = None) -> str:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json"} if not isinstance(payload, bytes) else {}
    hdrs.update(headers or {})
    try:
        http(url, data=body, headers=hdrs, timeout=15)
        return "sent"
    except Exception as e:
        return f"failed: {type(e).__name__}: {e}"[:160]


def ascii_only(s: str) -> str:
    return s.encode("ascii", "ignore").decode().strip()


def send_alerts(cfg: dict, items: list[dict], level: dict, test: bool = False) -> dict:
    ch = cfg.get("alerts", {}).get("channels", {})
    limit = int(cfg.get("alerts", {}).get("max_items_per_alert", 8))
    escalated = level.get("changed_from") is not None and level["value"] < level["changed_from"]
    if not test and not items and not escalated:
        return {}
    shown = items[:limit]
    n_crit = sum(it["severity"] == "critical" for it in items)
    head = f"SITCON {level['value']} {level['name']}"
    if test:
        title = f"{head}: test alert from The Situation Monitor"
    elif items:
        title = f"{head}: {len(items)} new report{'s' if len(items) != 1 else ''}" + (f", {n_crit} critical" if n_crit else "")
    else:
        title = f"{head}: level raised from {level['changed_from']}"
    def line(it):
        tag = f" [your stack: {', '.join(it['watch'])}]" if it.get("watch") else ""
        return f"{it['severity'].upper()} · {it['title']} ({it['source']}){tag}"
    more = f"\n…and {len(items) - limit} more" if len(items) > limit else ""
    plain = title + "\n" + "\n".join(f"- {line(it)} {it['url']}" for it in shown) + more
    results = {}
    if ch.get("slack_webhook"):
        esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        text = f"*{esc(title)}*\n" + "\n".join(f"• <{it['url']}|{esc(line(it))}>" if it["url"] else f"• {esc(line(it))}" for it in shown) + more
        results["slack"] = _post(ch["slack_webhook"], {"text": text, "unfurl_links": False, "unfurl_media": False})
    if ch.get("discord_webhook"):
        text = f"**{title}**\n" + "\n".join(f"- [{line(it)}](<{it['url']}>)" if it["url"] else f"- {line(it)}" for it in shown) + more
        results["discord"] = _post(ch["discord_webhook"], {"content": text[:1990], "allowed_mentions": {"parse": []}})
    if ch.get("teams_webhook"):
        body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title, "wrap": True}]
        body += [{"type": "TextBlock", "wrap": True, "spacing": "Small",
                  "text": f"[{line(it)}]({it['url']})" if it["url"] else line(it)} for it in shown]
        card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
        results["teams"] = _post(ch["teams_webhook"], {"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})
    if ch.get("ntfy_topic"):
        server = (ch.get("ntfy_server") or "https://ntfy.sh").rstrip("/")
        hdrs = {"Title": ascii_only(title)[:200], "Priority": "high" if n_crit or escalated else "default", "Tags": "rotating_light"}
        if shown and shown[0]["url"]:
            hdrs["Click"] = shown[0]["url"]
        results["ntfy"] = _post(f"{server}/{urllib.parse.quote(ch['ntfy_topic'])}",
                                ("\n".join(f"- {line(it)}" for it in shown) + more or title).encode("utf-8"), hdrs)
    if ch.get("webhook"):
        results["webhook"] = _post(ch["webhook"], {"event": "situation.alert", "title": title, "level": level,
                                                    "items": [dict(summary_row(it), watch=it.get("watch", [])) for it in items[:50]]})
    if ch.get("desktop") and sys.platform == "darwin":
        q = lambda s: '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
        msg = shown[0]["title"] if shown else title
        try:
            subprocess.run(["osascript", "-e", f"display notification {q(msg[:180])} with title {q(title[:90])}"],
                           check=False, timeout=10, capture_output=True)
            results["desktop"] = "sent"
        except Exception as e:
            results["desktop"] = f"failed: {e}"[:160]
    if not results and test:
        results["none"] = "no channels configured in config.json or SM_* environment variables"
    save_json(STATE / "last_alert.json", {"at": iso(now_utc()), "title": title, "plain": plain, "results": results})
    return results


# ---------------------------------------------------------------- run

def acquire_lock() -> bool:
    lock = STATE / ".lock"
    STATE.mkdir(parents=True, exist_ok=True)
    try:
        if lock.exists() and time.time() - lock.stat().st_mtime < 600:
            return False
    except OSError:
        pass
    lock.write_text(str(os.getpid()))
    return True


def release_lock() -> None:
    try:
        (STATE / ".lock").unlink()
    except OSError:
        pass


def run_sweep(cfg: dict, send: bool) -> dict:
    t0 = time.time()
    now = now_utc()
    sources = load_json(ROOT / "sources.json", [])
    meta = load_json(STATE / "meta.json", {})
    seen: dict[str, str] = load_json(STATE / "seen.json", {})
    baseline = not seen
    ctx = {"now": now, "vocab": set(meta.get("vocab", [])), "kev_cves": set(meta.get("kev_cves", []))}
    fetched, packages, status = sweep(sources, ctx)

    previous = load_json(STATE / "items.json", {"items": [], "packages": []})
    items = merge_items(previous.get("items", []), fetched, now)
    packages = merge_packages(previous.get("packages", []), packages, now)
    stamp = iso(now)
    new_ids = set()
    for it in items:
        if it["id"] in seen:
            it["first_seen"] = it.get("first_seen") or seen[it["id"]]
        else:
            it["first_seen"] = stamp
            seen[it["id"]] = stamp
            new_ids.add(it["id"])
    cutoff = iso(now - timedelta(days=30))
    seen = {k: v for k, v in seen.items() if v >= cutoff}

    meta.setdefault("first_sweep_at", stamp)
    meta["vocab"] = sorted(ctx["vocab"])
    meta["kev_cves"] = sorted(ctx["kev_cves"])
    meta["seen"] = seen
    data = build(items, packages, status, cfg, now, meta)
    for it in data["items"]:  # promoted packages get their first-seen stamp here
        if it["first_seen"] is None:
            it["first_seen"] = stamp
            if it["id"] not in seen:
                seen[it["id"]] = stamp
                new_ids.add(it["id"])

    new_items = sorted((it for it in data["items"] if it["id"] in new_ids and not baseline),
                       key=lambda it: (SEV_RANK[it["severity"]], it["published"]), reverse=True)
    alert_items = pick_alerts(new_items, cfg)
    write_outputs(data, new_items, alert_items)
    results = send_alerts(cfg, alert_items, data["level"]) if send and not baseline else {}

    meta.pop("seen", None)
    meta["level"] = {"value": data["level"]["value"], "since": data["level"]["since"]}
    meta["last_sweep_at"] = stamp
    save_json(STATE / "meta.json", meta)
    save_json(STATE / "seen.json", seen, compact=True)
    save_json(STATE / "items.json", {"items": [it for it in items], "packages": packages}, compact=True)
    save_json(STATE / "sources_status.json", status)
    return {"data": data, "new": new_items, "alerts": alert_items, "alert_results": results,
            "baseline": baseline, "seconds": round(time.time() - t0, 1), "status": status}


def run_rebuild(cfg: dict) -> dict:
    now = now_utc()
    meta = load_json(STATE / "meta.json", {})
    meta["seen"] = load_json(STATE / "seen.json", {})
    previous = load_json(STATE / "items.json", None)
    if not previous:
        sys.exit("Nothing to rebuild yet: run a sweep first (python3 monitor.py).")
    status = load_json(STATE / "sources_status.json", [])
    data = build(previous["items"], previous["packages"], status, cfg, now, meta)
    for it in data["items"]:
        it["first_seen"] = it.get("first_seen") or meta["seen"].get(it["id"]) or iso(now)
    data["generated_at"] = meta.get("last_sweep_at") or iso(now)
    data["rebuilt_at"] = iso(now)
    write_outputs(data, [], [])
    return data


def summary(result: dict) -> dict:
    data, new = result["data"], result["new"]
    sr = data.get("sitrep")
    return {
        "ok": True, "generated_at": data["generated_at"], "seconds": result["seconds"], "baseline": result["baseline"],
        "level": {k: data["level"][k] for k in ("value", "name", "changed_from", "reason", "heat")},
        "counts": {"items": len(data["items"]), "new": len(new),
                   "new_by_severity": dict(Counter(it["severity"] for it in new)),
                   "packages": len(data["packages"])},
        "sources_failed": [{"name": s["name"], "error": s["error"]} for s in result["status"] if not s["ok"]],
        "alerts_sent": result["alert_results"],
        "alert_items": [dict(summary_row(it), watch=it.get("watch", [])) for it in result["alerts"][:10]],
        "top_new": [summary_row(it) for it in new if it["severity"] in ("critical", "high")][:15],
        "situations": [{"name": s["name"], "outlets": s["source_count"], "severity": s["severity"]} for s in data["situations"][:6]],
        "sitrep_written_at": sr["written_at"] if sr else None,
        "files": {"live_store_doc": str(DATA / "live.json"), "situation": str(DATA / "situation.json")},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="The Situation Monitor sweep.")
    ap.add_argument("--summary", action="store_true", help="print a compact JSON summary after the sweep")
    ap.add_argument("--brief", action="store_true", help="print the current situation as text and exit")
    ap.add_argument("--rebuild", action="store_true", help="rebuild outputs from the last sweep without fetching")
    ap.add_argument("--no-alerts", action="store_true", help="sweep without sending alerts")
    ap.add_argument("--test-alert", action="store_true", help="send a test alert to every configured channel")
    ap.add_argument("--save-db-version", type=int, metavar="N", help="record the live-store document version")
    args = ap.parse_args(argv)
    cfg = load_config()

    if args.save_db_version is not None:
        art = load_json(STATE / "artifact.json", {})
        art.update({"version": args.save_db_version, "synced_at": iso(now_utc())})
        save_json(STATE / "artifact.json", art)
        print(json.dumps(art))
        return 0
    if args.brief:
        data = load_json(DATA / "situation.json", None)
        print(data["prompt_brief"] if data else "No sweep yet: run python3 monitor.py first.")
        return 0
    if args.test_alert:
        lv = {"value": 3, "name": "ELEVATED", "changed_from": None}
        print(json.dumps(send_alerts(cfg, [], lv, test=True), indent=1))
        return 0
    if not acquire_lock():
        print(json.dumps({"ok": False, "error": "another sweep is running (state/.lock is under 10 minutes old)"}))
        return 1
    try:
        if args.rebuild:
            data = run_rebuild(cfg)
            print(f"Rebuilt from the {data['generated_at']} sweep: SITCON {data['level']['value']} {data['level']['name']}, "
                  f"{len(data['items'])} items, SITREP {'present' if data.get('sitrep') else 'missing'}.")
            return 0
        result = run_sweep(cfg, send=not args.no_alerts)
    finally:
        release_lock()
    if args.summary:
        print(json.dumps(summary(result), ensure_ascii=False, indent=1))
    else:
        data = result["data"]
        failed = [s["name"] for s in result["status"] if not s["ok"]]
        print(f"SITCON {data['level']['value']} {data['level']['name']} · {len(data['items'])} items · "
              f"{len(result['new'])} new · {len(result['alerts'])} alert-worthy · "
              f"{data['stats']['sources_ok']}/{data['stats']['sources_total']} sources ok"
              + (f" (failed: {', '.join(failed)})" if failed else "") + f" · {result['seconds']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
