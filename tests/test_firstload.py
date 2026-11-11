"""The page's first load (P3-1): the board split between data/situation.json and data/more.json, and the
content written into index.html so the page reads without JavaScript."""
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import monitor as m  # noqa: E402

NOW = datetime(2026, 11, 11, 6, 0, tzinfo=timezone.utc)
APP = (ROOT / "site" / "app.html").read_text(encoding="utf-8")
HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)> & "quotes"'


def item(i, sev="high", type_="news", hours=0.0, **kw):
    it = {"id": f"i{i:04d}", "type": type_, "severity": sev, "title": f"Report {i}", "url": f"https://news.test/{i}",
          "source": "News", "source_id": "news", "published": m.iso(NOW - timedelta(hours=hours)), "summary": f"Summary {i}",
          "cves": [], "extra": {}, "tags": [], "first_seen": m.iso(NOW - timedelta(hours=hours))}
    it.update(kw)
    return it


def board_data():
    """A whole board as build() makes it: newest first, with every kind of item the split cares about."""
    items = [item(i, "critical" if i % 5 == 0 else "high", hours=i * 0.5) for i in range(200)]
    items += [item(300 + i, "medium", "ransomware", hours=i * 0.3, title=f"group claims victim{i}.test",
                   extra={"group": "qilin", "victim": f"victim{i}.test"}) for i in range(40)]
    items += [item(400 + i, "low", hours=i * 2 + 1) for i in range(30)]
    items += [item(500 + i, "medium", "breach", hours=i * 3 + 2) for i in range(10)]
    items += [item(600 + i, "critical", "kev", hours=150 + i, cves=[f"CVE-2026-{1000 + i}"],
                   extra={"vendor": "Acme", "product": f"Gateway {i}", "due": "2026-11-30", "ransomware": i == 0,
                          "date_only": True}) for i in range(5)]
    items += [item(700, "medium", "community", hours=4, tags=["ransomware"], extra={"hn_url": "https://news.ycombinator.com/item?id=1"})]
    old_member = item(800, "low", hours=300)
    items.append(old_member)
    items.sort(key=lambda it: it["published"], reverse=True)
    packages = [{"ghsa": f"GHSA-{i}", "ecosystem": "npm", "name": f"pkg{i}", "versions": ">= 0", "in_news": i == 35,
                 "published": m.iso(NOW - timedelta(hours=i)), "url": f"https://github.com/advisories/GHSA-{i}"} for i in range(40)]
    situation = {"name": "SSHole", "source_count": 4, "count": 2, "severity": "critical", "cves": ["CVE-2026-1"],
                 "first": m.iso(NOW - timedelta(days=2)), "last": m.iso(NOW - timedelta(hours=3)),
                 "items": ["i0003", old_member["id"]], "lead": {"title": "SSHole hits OpenSSH", "url": "https://news.test/3"}}
    level = {"value": 3, "name": "ELEVATED", "blurb": "Active campaigns.", "reason": "Ten critical reports.",
             "since": m.iso(NOW - timedelta(hours=20)), "changed_from": None, "pending": None, "heat": 300.0}
    data = {"schema": 1, "name": "The Situation Monitor", "generated_at": m.iso(NOW), "first_sweep_at": "2026-10-24T00:00:00Z",
            "window_days": 14, "site_url": "https://thesituationmonitor.org/", "feed_url": "https://thesituationmonitor.org/data/feed.xml",
            "repo_url": "https://github.com/theguysaccount/situation-monitor", "level": level, "situations": [situation],
            "sitrep": {"written_at": m.iso(NOW - timedelta(hours=2)), "by": "Claude", "headline": "SSHole is being exploited",
                       "bullets": [{"text": "Patch `openssh` today", "url": "https://news.test/3"}], "actions": ["Run `ssh -V`"]},
            "items": items, "packages": packages, "sources": [{"name": "News", "ok": True}],
            "stats": {"sources_ok": 25, "sources_total": 25, "critical_24h": 3, "high_24h": 9, "reports_24h": 40,
                      "kev_7d": 5, "kev_ransomware_7d": 1, "ransomware_24h": 40, "ransomware_7d": 40, "breaches_7d": 10,
                      "packages_72h": 40, "packages_ecosystems": {"npm": 30, "pip": 10}},
            "cves": {"since": "2021-11-03", "total": 1500, "ransomware": 300, "added_30d": 20, "added_prev_30d": 16,
                     "added_ytd": 200, "year": 2026, "recent": [["CVE-2026-1000", "Acme", "Gateway", "Acme Gateway RCE",
                                                                 "2026-11-10", "2026-11-30", True]]},
            "prompt": m.load_prompt_parts()}
    data["prompt_brief"] = "SITCON 3 of 5"
    return data


def js_object(name):
    """The string pairs of `const NAME = { ... };` in the page script."""
    body = re.search(r"const " + name + r" = \{(.*?)\};", APP, re.S).group(1)
    return dict(re.findall(r'"?([\w-]+)"?: "([^"]*)"', body))


class Split(unittest.TestCase):
    def setUp(self):
        self.data = board_data()
        self.board, self.rest = m.split_board(self.data, budget=10**9)
        self.first = {it["id"] for it in self.board["items"]}

    def test_first_file_has_what_the_page_shows_on_arrival(self):
        items = self.data["items"]
        priority = [it["id"] for it in items if it["severity"] in ("critical", "high")]
        self.assertTrue(set(priority[:150]) <= self.first)
        self.assertEqual(self.board["more"]["priority"], 150)
        self.assertTrue({it["id"] for it in items if it["type"] == "kev"} <= self.first)
        claims = [it["id"] for it in items if it["type"] == "ransomware"]
        self.assertEqual([i for i in claims if i in self.first], claims[:m.RAIL_CLAIMS])
        self.assertTrue({it["id"] for it in items if m.breach_panel(it)}.intersection(self.first) >=
                        {it["id"] for it in [i for i in items if m.breach_panel(i)][:m.RAIL_BREACHES]})
        self.assertTrue(set(self.data["situations"][0]["items"]) <= self.first)  # even a low, old member
        names = [p["name"] for p in self.board["packages"]]
        self.assertEqual(names[:m.BOARD_PACKAGES], [f"pkg{i}" for i in range(m.BOARD_PACKAGES)])
        self.assertIn("pkg35", names)  # in the news

    def test_second_file_has_everything_else_once(self):
        rest = [it["id"] for it in self.rest["items"]]
        self.assertFalse(self.first & set(rest))
        self.assertEqual(len(self.first) + len(rest), len(self.data["items"]))
        self.assertEqual(self.board["more"]["items"], len(rest))
        self.assertEqual(self.board["more"]["packages"], len(self.rest["packages"]))
        self.assertEqual(sum(it["type"] == "ransomware" for it in self.rest["items"]), 40 - m.RAIL_CLAIMS)
        self.assertEqual(sum(it["severity"] == "low" for it in self.rest["items"]), 30)
        self.assertEqual(self.rest["generated_at"], self.data["generated_at"])

    def test_tab_counts_cover_the_whole_board(self):
        counts = self.board["more"]["counts"]
        self.assertEqual(counts["all"], len(self.data["items"]))
        self.assertEqual(counts["priority"], 205)
        self.assertEqual(counts["ransomware"], 41)  # 40 claims and a Hacker News story tagged ransomware
        self.assertEqual(counts["community"], 1)
        self.assertEqual(counts["exploited"], 5)

    def test_a_small_budget_keeps_fewer_reports(self):
        board, rest = m.split_board(self.data, budget=1)
        self.assertEqual(board["more"]["priority"], m.BOARD_PRIORITY[-1])
        self.assertEqual(len(board["items"]) + len(rest["items"]), len(self.data["items"]))

    def test_joining_the_files_gives_back_the_board(self):
        whole = m.join_board(self.board, self.rest)
        self.assertNotIn("more", whole)
        self.assertEqual(sorted(it["id"] for it in whole["items"]), sorted(it["id"] for it in self.data["items"]))
        self.assertEqual([it["published"] for it in whole["items"]], [it["published"] for it in self.data["items"]])
        self.assertEqual([p["name"] for p in whole["packages"]], [p["name"] for p in self.data["packages"]])
        with self.assertRaises(ValueError):
            m.join_board(self.board, dict(self.rest, generated_at="2026-11-11T05:00:00Z"))
        self.assertIs(m.join_board(self.data, None), self.data)  # a board published before the split

    def test_filters_match_the_page_script(self):
        script = re.findall(r'\{ id: "([a-z]+)", label: "([^"]+)", test:', APP)
        self.assertEqual(script, [(fid, label) for fid, label, _ in m.FEED_FILTERS])

    def test_static_labels_match_the_page_script(self):
        self.assertEqual(js_object("KIND"), m.SSR_KIND)
        self.assertEqual(js_object("TAGS"), m.SSR_TAGS)
        self.assertEqual(js_object("SEV"), m.SSR_SEV)


class StaticHtml(unittest.TestCase):
    def render(self, data):
        return m.StaticPage(data).render(APP)

    def test_page_carries_the_briefing_level_situations_reports_and_cves(self):
        page = self.render(board_data())
        markup = page.split("<script>")[0]
        self.assertIn("SSHole is being exploited", markup)
        self.assertIn("Patch <code>openssh</code> today", markup)
        self.assertNotIn('id="sitrep" aria-labelledby="sitrep-head" hidden', markup)
        self.assertIn('<div class="cell lv3 on">3</div>', markup)
        self.assertIn('aria-label="SITCON 3 of 5: ELEVATED"', markup)
        self.assertIn('<p class="board-name" id="board-name">ELEVATED</p>', markup)
        self.assertIn('<h3 class="sit-name">SSHole</h3>', markup)
        self.assertEqual(len(re.findall(r'<a href="https://news\.test/\d+" class="row-title"', markup)), m.STATIC_REPORTS)
        self.assertIn("CVE-2026-1000", markup)
        self.assertIn('<span class="n">205</span>', markup)  # the Priority tab counts the whole board
        self.assertIn("Swept 06:00 UTC", markup)
        self.assertEqual(page.split("<script>", 1)[1], APP.split("<script>", 1)[1])  # the script is untouched

    def test_feed_text_is_escaped_and_only_web_links_are_written(self):
        data = board_data()
        lead = next(it for it in data["items"] if it["severity"] == "critical")
        lead.update(title=HOSTILE, summary=HOSTILE, url="javascript:alert(3)", source=HOSTILE, tags=["zero-day"])
        data["situations"][0].update(name=HOSTILE, lead={"title": HOSTILE, "url": "javascript:alert(4)"})
        data["sitrep"].update(headline=HOSTILE, bullets=[{"text": HOSTILE, "url": "javascript:alert(5)"}], actions=[HOSTILE])
        data["level"]["reason"] = HOSTILE
        markup = self.render(data).split("<script>")[0]
        self.assertNotIn("<script>alert", markup)
        self.assertNotIn("<img src=x", markup)
        self.assertNotIn("javascript:", markup)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", markup)
        self.assertIn("&quot;quotes&quot;", markup)

    def test_without_a_briefing_its_section_stays_hidden(self):
        data = board_data()
        data["sitrep"] = None
        self.assertIn('id="sitrep" aria-labelledby="sitrep-head" hidden', self.render(data))

    def test_a_rendering_error_leaves_the_template(self):
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(m.static_page(APP, {"generated_at": m.iso(NOW)}), APP)
        self.assertIn("warning", err.getvalue())
        with self.assertRaises(ValueError):
            m.fill_element(APP, "no-such-element", "x")

    def test_fill_element_handles_nesting_and_attributes(self):
        page = '<div id="a" hidden title="t"><div>1</div><div>2</div></div><p>after</p>'
        out = m.fill_element(page, "a", "<b>x</b>", {"hidden": None, "title": 'say "hi"'})
        self.assertEqual(out, '<div id="a" title="say &quot;hi&quot;"><b>x</b></div><p>after</p>')


class Outputs(unittest.TestCase):
    """write_outputs: the two board files, the page, and the files that keep the whole board."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        site = Path(self.tmp.name) / "site"
        site.mkdir()
        (site / "app.html").write_text(APP, encoding="utf-8")
        self.site = site
        self.patches = [mock.patch.object(m, "SITE", site), mock.patch.object(m, "DATA", site / "data"),
                        mock.patch.object(m, "load_config", lambda: {})]
        for p in self.patches:
            p.start()
        self.data = board_data()
        m.write_outputs(self.data, [], [])

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def read(self, name):
        return json.loads((self.site / "data" / name).read_text(encoding="utf-8"))

    def test_the_two_files_make_the_whole_board(self):
        board, rest = self.read("situation.json"), self.read("more.json")
        self.assertIn("more", board)
        self.assertEqual(len(m.join_board(board, rest)["items"]), len(self.data["items"]))

    def test_first_load_fits_the_budget(self):
        page = (self.site / "index.html").read_text(encoding="utf-8")
        self.assertLessEqual(m.gzip_size(page) + m.gzip_size(self.read("situation.json")),
                             m.FIRST_LOAD_BUDGET - m.FIRST_LOAD_SLACK)
        self.assertIn('<link rel="canonical"', page)
        self.assertIn("SSHole is being exploited", page)

    def test_feed_changes_and_live_copy_still_cover_the_whole_board(self):
        live = self.read("live.json")
        self.assertNotIn("more", live)
        self.assertTrue(any(it["type"] == "ransomware" for it in live["items"]))
        changes = self.read("changes.json")
        self.assertEqual(len(changes["items"]), sum(it["severity"] in ("critical", "high") for it in self.data["items"]
                                                    if it["first_seen"] >= m.iso(NOW - timedelta(days=7))))
        feed = (self.site / "data" / "feed.xml").read_text(encoding="utf-8")
        self.assertEqual(feed.count("<item>"), 80)
        prompt = (self.site / "data" / "master-prompt.md").read_text(encoding="utf-8")
        self.assertEqual(prompt.count("</situation_data"), 1)


if __name__ == "__main__":
    unittest.main()
