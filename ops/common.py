"""Shared helpers for the ops scripts: HTTP, sitemaps, TLS, Pages builds and Actions output.

Standard library only; Python 3.9+.
"""
from __future__ import annotations

import gzip
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

UA = "Mozilla/5.0 (compatible; situation-monitor-ops/1.0; +https://github.com/theguysaccount/situation-monitor)"
# Some government sites refuse unknown agents outright; the link checker identifies as a browser.
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def fetch(url: str, *, follow: bool = True, timeout: int = 25, tries: int = 2, ua: str = UA,
          limit: int = 5_000_000) -> tuple[int, str, dict, bytes, str]:
    """GET a URL. Returns (status, final_url, headers, body, error); status 0 means no answer."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.8"}
    result = (0, url, {}, b"", "no attempt")
    for attempt in range(tries):
        if attempt:
            time.sleep(4 * attempt)
        try:
            with opener.open(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
                return r.status, r.geturl(), {k.lower(): v for k, v in r.headers.items()}, r.read(limit), ""
        except urllib.error.HTTPError as e:
            try:
                body = e.read(limit)
            except Exception:
                body = b""
            result = (e.code, url, {k.lower(): v for k, v in (e.headers or {}).items()}, body, f"HTTP {e.code}")
            if e.code < 500 and e.code != 429:
                return result
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            result = (0, url, {}, b"", f"{type(reason).__name__}: {reason}")
    return result


def sitemap_locs(body: bytes) -> tuple[str, list[str]]:
    """('urlset'|'sitemapindex'|'', locs) for a sitemap document."""
    try:
        root = ET.fromstring(gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body)
    except (ET.ParseError, OSError, EOFError):
        return "", []
    kind = root.tag.rsplit("}", 1)[-1]
    locs = [el.text.strip() for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "loc" and el.text]
    return (kind, locs) if kind in ("urlset", "sitemapindex") else ("", [])


def tls_days_left(host: str, port: int = 443) -> float:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=20) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            cert = s.getpeercert()
    return (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400


def github_api(path: str) -> tuple[int, object]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    req = urllib.request.Request(f"https://api.github.com/{path.lstrip('/')}", headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": UA,
        **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None


def wait_for_pages_build(repo: str, sha: str, timeout: int = 900) -> tuple[bool, str]:
    """Wait for the branch-deploy Pages build of `sha`. Returns (built, detail)."""
    deadline = time.time() + timeout
    last = "no build seen yet"
    while time.time() < deadline:
        status, builds = github_api(f"repos/{repo}/pages/builds?per_page=20")
        if status == 200 and isinstance(builds, list):
            mine = [b for b in builds if b.get("commit") == sha]
            if mine:
                b = mine[0]
                last = f"build for {sha[:7]} is {b.get('status')}"
                if b.get("status") == "built":
                    return True, last
                if b.get("status") == "errored":
                    return False, f"{last}: {(b.get('error') or {}).get('message')}"
        else:
            last = f"Pages builds API answered {status}"
        time.sleep(20)
    return False, f"timed out after {timeout}s ({last})"


def annotate(level: str, msg: str) -> None:
    """A GitHub Actions annotation (shown on the run page); plain text elsewhere."""
    msg = msg.replace("\n", " ")
    print(f"::{level}::{msg}" if os.environ.get("GITHUB_ACTIONS") else f"{level.upper()}: {msg}", flush=True)


def summary(markdown: str) -> None:
    """Append to the run's job summary when running in Actions."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(markdown.rstrip() + "\n\n")


class Checks:
    """Collects pass, warn and fail results, then reports them and returns an exit code."""

    def __init__(self, title: str):
        self.title, self.rows = title, []

    def ok(self, name: str, detail: str = "") -> None:
        self.rows.append(("ok", name, detail))
        print(f"ok    {name} {detail}".rstrip(), flush=True)

    def warn(self, name: str, detail: str) -> None:
        self.rows.append(("warn", name, detail))
        annotate("warning", f"{name}: {detail}")

    def fail(self, name: str, detail: str) -> None:
        self.rows.append(("fail", name, detail))
        annotate("error", f"{name}: {detail}")

    def finish(self) -> int:
        fails = sum(1 for r in self.rows if r[0] == "fail")
        warns = sum(1 for r in self.rows if r[0] == "warn")
        icon = {"ok": "✅", "warn": "⚠️", "fail": "❌"}
        lines = [f"### {self.title}: {'FAILED' if fails else 'passed'} "
                 f"({len(self.rows)} checks, {fails} failed, {warns} warnings)", "", "| | Check | Detail |", "|---|---|---|"]
        lines += [f"| {icon[s]} | {n} | {d.replace('|', '/')} |" for s, n, d in self.rows if s != "ok" or len(self.rows) <= 40]
        summary("\n".join(lines))
        print(f"{self.title}: {len(self.rows)} checks, {fails} failed, {warns} warnings", flush=True)
        return 1 if fails else 0
