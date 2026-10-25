"""Tests for the pre-deploy gate (ops/check_build.py) against a synthetic site/ directory."""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ops"))
import check_build  # noqa: E402

KEY = "0123456789abcdef0123456789abcdef"


def stamp(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.site = Path(self.tmp.name)
        (self.site / "data").mkdir()
        (self.site / "index.html").write_text(
            '<head><link rel="canonical" href="https://x.test/"><title>The Situation Monitor</title></head>' + "x" * 12000)
        self.data = {"generated_at": stamp(), "site_url": "https://x.test/", "items": [{"id": "a"}],
                     "stats": {"sources_ok": 24, "sources_total": 25},
                     "sources": [{"name": "CISA Advisories", "ok": False}]}
        self.write_data()
        (self.site / "data" / "live.json").write_text("{}")
        (self.site / "data" / "feed.xml").write_text('<?xml version="1.0"?><rss version="2.0"><channel/></rss>')
        (self.site / "data" / "master-prompt.md").write_text('# Prompt\n<situation_data generated="x">brief</situation_data>\n')
        (self.site / "sitemap.xml").write_text(
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://x.test/</loc></url></urlset>')
        (self.site / "robots.txt").write_text("User-agent: *\nAllow: /\n\nSitemap: https://x.test/sitemap.xml\n")
        (self.site / f"{KEY}.txt").write_text(KEY)

    def tearDown(self):
        self.tmp.cleanup()

    def write_data(self):
        (self.site / "data" / "situation.json").write_text(json.dumps(self.data))

    def gate(self):
        with redirect_stdout(io.StringIO()):
            return check_build.run(self.site)

    def test_good_site_passes(self):
        self.assertEqual(self.gate(), 0)

    def test_stale_data_blocks_deploy(self):
        self.data["generated_at"] = stamp(minutes_ago=90)
        self.write_data()
        self.assertEqual(self.gate(), 1)

    def test_too_few_sources_blocks_deploy(self):
        self.data["stats"] = {"sources_ok": 10, "sources_total": 25}
        self.write_data()
        self.assertEqual(self.gate(), 1)

    def test_empty_board_blocks_deploy(self):
        self.data["items"] = []
        self.write_data()
        self.assertEqual(self.gate(), 1)

    def test_unfilled_prompt_blocks_deploy(self):
        (self.site / "data" / "master-prompt.md").write_text("<situation_data>{{SITUATION_BRIEF}}</situation_data>")
        self.assertEqual(self.gate(), 1)

    def test_broken_feed_blocks_deploy(self):
        (self.site / "data" / "feed.xml").write_text("<rss><channel>")
        self.assertEqual(self.gate(), 1)

    def test_missing_indexnow_key_blocks_deploy(self):
        (self.site / f"{KEY}.txt").unlink()
        self.assertEqual(self.gate(), 1)

    def test_repo_ships_an_indexnow_key(self):
        keys = [p for p in (ROOT / "site").glob("*.txt") if len(p.stem) == 32]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].read_text().strip(), keys[0].stem)
        self.assertIn(keys[0].name, (ROOT / ".github/workflows/situation-monitor.yml").read_text())


if __name__ == "__main__":
    unittest.main()
