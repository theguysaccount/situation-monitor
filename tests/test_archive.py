"""Tests for the data-branch archive (ops/archive.py). Run: python3 -m unittest discover -s tests"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ops"))
import archive  # noqa: E402


def item(id_, typ, sev, published, first_seen, title=None, **extra):
    return {"id": id_, "type": typ, "severity": sev, "title": title or f"Story {id_}", "source": "Example",
            "url": f"https://example.com/{id_}", "published": published, "first_seen": first_seen, "cves": [],
            "summary": "", "tags": [], "extra": extra}


class Archive(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.state, self.site, self.arc = t / "state", t / "site", t / "archive"
        for d in (self.state, self.site / "data", self.arc):
            d.mkdir(parents=True)
        items = [item("a", "news", "critical", "2026-11-10T09:00:00Z", "2026-11-10T09:13:00Z"),
                 item("b", "news", "low", "2026-11-10T10:00:00Z", "2026-11-10T10:13:00Z"),
                 item("k", "kev", "critical", "2026-11-10T00:00:00Z", "2026-11-10T15:13:00Z",
                      title="CVE-2026-1: Acme Widget flaw", vendor="Acme", product="Widget", due="2026-11-24"),
                 item("r1", "ransomware", "medium", "2026-11-10T02:00:00Z", "2026-11-10T02:13:00Z", group="qilin"),
                 item("r2", "ransomware", "medium", "2026-11-10T03:00:00Z", "2026-11-10T03:13:00Z", group="qilin")]
        items[2]["cves"] = ["CVE-2026-1"]
        (self.state / "items.json").write_text(json.dumps({"items": items, "packages": []}))
        (self.state / "history.json").write_text(json.dumps({"sitcon": [["2026-11-10T09:13:00Z", 3, 300.0],
                                                                        ["2026-11-10T10:13:00Z", 2, 420.0],
                                                                        ["2026-11-11T00:13:00Z", 2, 410.0]]}))
        (self.state / "meta.json").write_text(json.dumps({"vocab": []}))
        (self.state / "seen.json").write_text("{}")
        self.publish("2026-11-11T00:43:00Z")
        self.sitrep = Path(self.tmp.name) / "sitrep.json"
        self.sitrep.write_text(json.dumps({"written_at": "2026-11-11T03:40:00Z", "headline": "h", "bullets": [], "actions": []}))

    def tearDown(self):
        self.tmp.cleanup()

    def publish(self, generated_at):
        (self.site / "data" / "situation.json").write_text(json.dumps({"generated_at": generated_at}))

    def save(self):
        return archive.save(self.state, self.site, self.arc, self.sitrep)

    def test_first_save_writes_yesterday_the_briefing_and_the_memory(self):
        changed = self.save()
        self.assertIn("days/2026-11-10.json", changed)
        # The briefing is stamped 03:40 by a fast clock but published by the 00:43 sweep: it is filed at 00:43.
        self.assertIn("sitreps/2026-11-11/004300Z.json", changed)
        self.assertTrue((self.arc / "state" / "items.json").exists())
        day = json.loads((self.arc / "days" / "2026-11-10.json").read_text())
        self.assertEqual(day["sitcon"]["hours_at_level"], {"3": 1, "2": 1})
        self.assertEqual(day["sitcon"]["highest"], 2)
        self.assertEqual([r["title"] for r in day["top_reports"]], ["Story a"])
        self.assertEqual(day["kev_added"][0]["cve"], "CVE-2026-1")
        self.assertEqual(day["ransomware_claims"], {"count": 2, "groups": [["qilin", 2]]})
        self.assertEqual(day["first_seen"]["count"], 5)

    def test_later_sweeps_the_same_day_change_nothing(self):
        self.save()
        self.publish("2026-11-11T13:43:00Z")
        self.assertEqual(self.save(), [])

    def test_the_next_day_is_written_once_it_is_over(self):
        self.save()
        self.publish("2026-11-12T00:13:00Z")
        changed = self.save()
        self.assertEqual(changed[:1], ["days/2026-11-11.json"])
        self.assertIn("state/", changed)
        day = json.loads((self.arc / "days" / "2026-11-11.json").read_text())
        self.assertEqual(day["sitreps"], ["sitreps/2026-11-11/004300Z.json"])

    def test_an_empty_cache_is_restored_from_the_archive(self):
        self.save()
        fresh = Path(self.tmp.name) / "fresh-state"
        self.assertTrue(archive.restore(fresh, self.arc))
        self.assertEqual(json.loads((fresh / "items.json").read_text())["items"][0]["id"], "a")
        self.assertFalse(archive.restore(fresh, self.arc))  # never overwrites memory that exists

    def test_the_fast_clock_window_comes_from_push_times(self):
        commits = [("s1", "2026-11-02T10:00:00Z"), ("s2", "2026-11-04T13:19:00Z"), ("s3", "2026-11-09T16:19:00Z"),
                   ("s4", "2026-11-11T03:01:00Z")]
        pushed = {"s1": "2026-11-02T10:00:20Z", "s2": "2026-11-04T10:19:30Z", "s3": "2026-11-09T13:19:30Z",
                  "s4": "2026-11-11T03:01:30Z"}
        start, end, skew = archive.clock_window(commits, pushed)
        self.assertEqual((start, end), ("2026-11-04T12:19:00Z", "2026-11-09T16:19:00Z"))
        self.assertAlmostEqual(skew, 10770, delta=60)


if __name__ == "__main__":
    unittest.main()
