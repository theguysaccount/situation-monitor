"""Offline tests for monitor.py's parsing, scoring and rendering. Run: python3 -m unittest discover -s tests"""
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import monitor as m  # noqa: E402

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Hackers actively exploit zero-day in FortiGate firewalls</title>
<link>https://example.com/a?utm_source=rss&amp;id=7</link><pubDate>Sat, 24 Oct 2026 10:00:00 GMT</pubDate>
<description>&lt;p&gt;CVE-2026-12345 is being exploited.&lt;/p&gt; The post Foo appeared first on Bar</description></item>
</channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Atom story</title>
<link rel="alternate" href="https://example.org/b"/><updated>2026-10-24T09:30:00Z</updated><summary>s</summary></entry></feed>"""
SLOPPY = b"""<rss><channel><item><title>Tom & Jerry breach</title><link>https://x.test/c</link></item></channel></rss>"""


class Parsing(unittest.TestCase):
    def test_rss(self):
        (e,) = m.parse_feed(RSS)
        self.assertEqual(e["title"], "Hackers actively exploit zero-day in FortiGate firewalls")
        self.assertTrue(e["link"].startswith("https://example.com/a"))
        self.assertEqual(m.parse_date(e["date"]), datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc))

    def test_atom_and_sloppy_xml(self):
        self.assertEqual(m.parse_feed(ATOM)[0]["link"], "https://example.org/b")
        self.assertEqual(m.parse_feed(SLOPPY)[0]["title"], "Tom & Jerry breach")

    def test_dates(self):
        self.assertEqual(m.parse_iso("2026-10-24T10:00:00+02:00"), datetime(2026, 10, 24, 8, 0, tzinfo=timezone.utc))
        self.assertIsNone(m.parse_iso("yesterday"))
        self.assertEqual(m.iso(NOW), "2026-10-25T12:00:00Z")

    def test_urls(self):
        self.assertEqual(m.strip_tracking("https://a.test/x?utm_source=rss&id=7"), "https://a.test/x?id=7")
        self.assertEqual(m.strip_tracking("http://abc.onion/x"), "")
        self.assertEqual(m.strip_tracking("javascript:alert(1)"), "")
        self.assertEqual(m.canon_url("https://www.A.test/story/amp/"), "a.test/story")

    def test_clean(self):
        self.assertEqual(m.clean("<p>Hello&amp;nbsp;<b>world</b></p> Read more"), "Hello world")
        self.assertTrue(m.clean("word " * 100, 40).endswith("…"))


class Scoring(unittest.TestCase):
    def sev(self, title, summary=""):
        return m.sev_from_score(m.keyword_score(title, summary)[0])

    def test_severity(self):
        self.assertEqual(self.sev("Hackers actively exploit zero-day in FortiGate firewalls"), "critical")
        self.assertEqual(self.sev("Worm spreads through malicious npm packages in supply chain attack"), "critical")
        self.assertEqual(self.sev("Malicious npm package steals API keys in supply chain attack"), "high")
        self.assertEqual(self.sev("Company appoints new CISO"), "low")

    def test_roundups_and_commentary_capped(self):
        self.assertIn(self.sev("Weekly recap: zero-day, ransomware, supply chain worm"), ("low", "medium"))
        self.assertIn(self.sev("Five things to know", "actively exploited zero-day supply chain worm"), ("low", "medium"))

    def test_make_item_ids_and_cves(self):
        src = {"id": "s", "name": "Source"}
        a = m.make_item(src, "news", "Bug CVE-2026-1111 fixed", "https://www.a.test/x?utm_source=1", NOW)
        b = m.make_item(src, "news", "Same story, new title", "https://a.test/x/", NOW)
        self.assertEqual(a["id"], b["id"])  # same canonical URL, same incident
        self.assertEqual(a["cves"], ["CVE-2026-1111"])

    def test_level(self):
        quiet = m.compute_level([], [], NOW, m.DEFAULT_THRESHOLDS)
        self.assertEqual(quiet["value"], 5)
        hot = [{"type": "kev", "published": m.iso(NOW - timedelta(hours=1)), "severity": "critical"}] * 30
        self.assertLess(m.compute_level(hot, [], NOW, m.DEFAULT_THRESHOLDS)["value"], 5)


class Rendering(unittest.TestCase):
    data = {
        "site_url": "https://thesituationmonitor.org/", "generated_at": "2026-10-25T12:00:00Z",
        "items": [{"id": "abc", "severity": "critical", "title": "A <b> & C", "url": "https://x.test/1",
                   "published": "2026-10-25T11:00:00Z", "type": "news", "source": "S", "summary": "sum & more"}],
    }

    def test_rss_and_sitemap_are_valid_xml(self):
        rss = ET.fromstring(m.rss(self.data).encode())
        self.assertEqual(rss.find("./channel/item/title").text, "[CRITICAL] A <b> & C")
        sm = ET.fromstring(m.sitemap(self.data).encode())
        self.assertEqual(sm[0][0].text, "https://thesituationmonitor.org/")

    def test_page_head_has_canonical_and_share_tags(self):
        head = m.page_head(self.data, {})
        self.assertIn('<link rel="canonical" href="https://thesituationmonitor.org/">', head)
        self.assertIn('property="og:image"', head)

    def test_master_prompt_template_has_its_parts(self):
        parts = m.load_prompt_parts()
        self.assertIn("<situation_data", parts["template"])
        self.assertTrue(parts["run_mode"]["code"] and parts["alerts"]["nofeed"])


class Cli(unittest.TestCase):
    def test_brief_runs_without_network(self):
        out = subprocess.run([sys.executable, str(ROOT / "monitor.py"), "--brief"], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(out.stdout.strip())


if __name__ == "__main__":
    unittest.main()
