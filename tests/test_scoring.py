"""Severity scoring measured against 300 hand-labelled headlines.

tests/fixtures/scoring_gold.json holds news items taken from the live board on 2026-11-10.
Each is labelled by hand with one question: should a security team hear about this today?

  alert: true   a confirmed breach, theft, ransomware or destructive attack on a named
                organisation; active exploitation or a zero-day; a malicious package,
                extension or release; a critical flaw or emergency patch in widely used
                software; an active campaign by a named actor.
  alert: false  commentary, advice and explainers; surveys, reports and predictions; product,
                business and funding news; courts, arrests, sanctions, settlements and policy;
                research without an active threat; routine patch batches; roundups and podcasts;
                botnet takedowns.

"Alerting" means scoring high or critical. The split is fixed by a hash of each id: 30% is
held out. Change the rules in monitor.py by looking only at mistakes on the "tune" items
(python3 tests/test_scoring.py prints them), then check the held-out score here.

Run: python3 -m unittest tests.test_scoring -v
"""
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import monitor as m  # noqa: E402

GOLD = json.loads((ROOT / "tests" / "fixtures" / "scoring_gold.json").read_text())
FLOOR = 0.85


def alerts(title: str, summary: str = "") -> bool:
    return m.sev_from_score(m.keyword_score(title, summary)[0]) in ("high", "critical")


def measure(split=None) -> dict:
    tp = fp = fn = tn = 0
    misses = []
    for g in GOLD:
        if split and g["split"] != split:
            continue
        got = alerts(g["title"], g["summary"])
        tp += got and g["alert"]
        fp += got and not g["alert"]
        fn += not got and g["alert"]
        tn += not got and not g["alert"]
        if got != g["alert"]:
            misses.append(("false alarm" if got else "missed") + ": " + g["title"])
    return {"precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1), "n": tp + fp + fn + tn,
            "misses": misses}


def report(name: str, r: dict) -> str:
    return f"{name}: precision {r['precision']:.3f}, recall {r['recall']:.3f} on {r['n']} items"


class GoldSet(unittest.TestCase):
    def test_split_is_fixed_by_id(self):
        for g in GOLD:
            held = int(hashlib.sha256(g["id"].encode()).hexdigest()[:8], 16) % 10 < 3
            self.assertEqual(g["split"], "holdout" if held else "tune", g["title"])
        self.assertEqual(len(GOLD), 300)

    def test_held_out_precision_and_recall(self):
        held, tune = measure("holdout"), measure("tune")
        lines = [report("Severity scoring, held-out", held), report("Severity scoring, tune", tune)]
        sys.stderr.write("\n" + "\n".join(lines) + "\n")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as f:
                f.write("\n".join(["### Severity scoring vs the hand-labelled set", ""] + [f"- {x}" for x in lines]) + "\n")
        self.assertGreaterEqual(held["precision"], FLOOR, lines[0])
        self.assertGreaterEqual(held["recall"], FLOOR, lines[0])


class Examples(unittest.TestCase):
    """Headlines that were scored wrong on the live board in November 2026."""

    def sev(self, title, summary=""):
        return m.sev_from_score(m.keyword_score(title, summary)[0])

    def test_real_incidents_alert(self):
        for title in [
            "SEGA newsletter data breach exposes 2.2 million email addresses",
            "Plex2Shell Exploited Against QNAP NAS Users",
            "Norway's aid agency pwned and all users' data is stolen",
            "Suspected Chinese attackers built a custom PHP2Shell exploit and rooted 25 servers",
            "CISA Warns of Node2Shell Exploitation as Honeypots Log Attack Attempts",
            "China-backed threat group used agentic AI pentesting tool to compromise 140 sensitive targets",
        ]:
            self.assertIn(self.sev(title), ("high", "critical"), title)

    def test_commentary_and_aftermath_do_not(self):
        for title in [
            "What a security leader should tell the CEO about leaked credentials",
            "Serial ransomware crook gets 70 months behind bars for Nefilim, Hive roles",
            "HHS' Office for Civil Rights Settles Ransomware Investigation of Lehigh Valley Health Network",
            "GitHub Launches npm Firewall to Block Malicious Packages Before Installation",
            "UK Cyber Chief Says the UK Will Face AI Cyberattacks on Critical Infrastructure by 2028",
        ]:
            self.assertIn(self.sev(title), ("low", "medium"), title)
        # "appointments" is not "appoints": a real attack must not be mistaken for a hiring story.
        self.assertIn(self.sev("Cyberattack forces University of New Mexico Health to divert ambulances, "
                               "cancel appointments"), ("high", "critical"))

    def test_critical_needs_something_to_patch_or_hunt(self):
        self.assertEqual(self.sev("Hackers exploit SSHole OpenSSH flaw to breach Linux systems"), "critical")
        self.assertEqual(self.sev("Max-Severity GitLab Vulnerability Exploited Against Alpine Linux"), "critical")
        # A big breach with attribution is serious, but there is nothing to patch: high, not critical.
        self.assertEqual(self.sev("FBI links $6.3 billion Binance crypto heist to North Korean hackers"), "high")
        self.assertEqual(self.sev("Hackers Steal 2.6 Million Records From Sony's Japanese ISP So-net"), "high")


if __name__ == "__main__":
    for split in ("tune", "holdout"):
        r = measure(split)
        print(report(split, r))
        if split == "tune":
            print("\n".join("  " + x for x in r["misses"]))
