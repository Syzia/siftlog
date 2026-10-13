"""Acceptance for the detection stages (3 and 4).

Stage 3: every count-based attack fires exactly one alert, benign traffic none.
Stage 4: impossible travel and "failures then success" fire, legitimate travel does not.

Measured through the real pipeline (simulator -> log file -> parser -> SQLite
store -> location enrichment -> replay engine) and scored against ground truth.
"""
import contextlib
import io
import os
import tempfile
import unittest

from siftlog.enrich import TableGeoResolver
from siftlog.engine import ReplayEngine, load_rules, score
from siftlog.engine.__main__ import main as engine_cli
from siftlog.evaluate import (
    evaluate,
    file_event_scenarios,
    grouping_note,
    knob,
    simulated_dataset,
    threshold_sweep,
    with_knob,
)
from siftlog.ingest import ingest_file
from siftlog.parsers import SshdParser
from siftlog.simulator import FAKE_GEO, load_labels, simulate, write_files
from siftlog.store import EventStore

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
ALL_RULES = ("ssh-brute-force", "ssh-credential-stuffing", "ssh-impossible-travel",
             "ssh-password-spray", "ssh-success-after-failures")  # fmt: skip
# The one alert the rules are known to get wrong: a real user on a VPN (see the simulator).
VPN_FALSE_ALARM = "ssh-impossible-travel on vera"
CLEAN_BENIGN = ("typo_benign", "nat_office", "legit_travel", "monitor_probe")


class EndToEndFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log, self.labels_path, self.db = (
            os.path.join(self.tmp.name, n) for n in ("sim.log", "sim.labels.json", "events.db")
        )
        write_files(simulate(seed=1234), self.log, self.labels_path)
        self.rules = load_rules(RULES_DIR)
        with EventStore(self.db) as store:
            self.assertEqual(ingest_file(self.log, SshdParser(year=2026), store).dead_letters, 0)

    def run_engine(self):
        with EventStore(self.db) as store:
            return ReplayEngine(self.rules).run(store.iter_events()), {e.id for e in store.iter_events()}

    def report(self, alerts):
        labels = load_labels(self.labels_path)
        truth = file_event_scenarios(self.log, self.labels_path)
        return score(labels, alerts, [r.id for r in self.rules], truth)

    def test_log_file_to_scored_alerts(self):
        with EventStore(self.db) as store:
            self.assertGreater(store.backfill_geo(TableGeoResolver(FAKE_GEO))[0], 0)
        alerts, stored_ids = self.run_engine()

        expected = [pair for label in load_labels(self.labels_path) for pair in label.expected_alerts]
        self.assertEqual(len(expected), 6)  # five attacks we should catch, one of which trips two rules
        self.assertEqual(sorted((a.rule_id, a.group_key) for a in alerts),
                         sorted(expected + [("ssh-impossible-travel", "vera")]))
        for a in alerts:  # every alert links back to real stored events
            self.assertTrue(a.evidence_event_ids)
            self.assertTrue(set(a.evidence_event_ids) <= stored_ids)

        report = self.report(alerts)
        for rule_id in ALL_RULES:
            row = report.rule(rule_id)
            self.assertEqual((row.detected, row.duplicate_alerts, row.bonus_alerts), (row.expected, 0, 0), rule_id)
            self.assertTrue(row.loaded)
        self.assertEqual(report.missed, ())
        self.assertEqual(report.false_alert_details, (VPN_FALSE_ALARM,))
        self.assertEqual(report.documented_misses, ("low_and_slow-0",))
        self.assertEqual((report.attacks, report.attacks_detected), (6, 5))

        carol = next(a for a in alerts if a.group_key == "carol")
        self.assertIn("London -> Sydney", carol.summary)
        self.assertFalse(any(a.group_key == "bob" for a in alerts))  # the legitimate traveller

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            engine_cli(["--db", self.db, "--rules", RULES_DIR, "--labels", self.labels_path, "--log", self.log])
        self.assertIn("7 alert(s) from 8 rule(s)", out.getvalue())
        self.assertIn("London -> Sydney", out.getvalue())
        # The honeypot rules cannot fire on sshd data, so they are named, not given a row of zeros.
        self.assertNotIn("| `honeypot-", out.getvalue())
        self.assertIn("Not scored (3 rule(s) that do not read sshd events): honeypot-", out.getvalue())

    def test_travel_rule_sees_nothing_until_events_are_located(self):
        alerts, _ = self.run_engine()  # no enrichment step
        self.assertFalse(any(a.rule_id == "ssh-impossible-travel" for a in alerts))
        self.assertEqual(self.report(alerts).missed, ("impossible_travel-0",))


class ManySeedTests(unittest.TestCase):
    N = 20

    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(RULES_DIR)
        cls.datasets = [simulated_dataset(seed) for seed in range(1, cls.N + 1)]

    def sweep(self, rule_id, values):
        return dict(threshold_sweep(self.rules, rule_id, values, self.datasets))

    def test_every_rule_catches_its_attacks_in_every_run(self):
        report = evaluate(self.rules, self.datasets)
        n = self.N
        want = {  # rule: (expected, alerts, false)
            "ssh-brute-force": (2 * n, 2 * n, 0),  # the plain brute force and the one that succeeds
            "ssh-credential-stuffing": (n, n, 0),
            "ssh-password-spray": (n, n, 0),
            "ssh-success-after-failures": (n, n, 0),
            "ssh-impossible-travel": (n, 2 * n, n),  # every run: one stolen login, one VPN user
        }
        for rule_id, (expected, alerts, false) in want.items():
            row = report.rule(rule_id)
            self.assertEqual(
                (row.expected, row.detected, row.alerts, row.false_alerts, row.duplicate_alerts, row.bonus_alerts),
                (expected, expected, alerts, false, 0, 0), rule_id,
            )
        self.assertEqual(report.missed, ())
        self.assertEqual(report.recall, 1.0)
        # The only false alerts are the documented one, once per run.
        self.assertEqual(report.false_alert_details, (VPN_FALSE_ALARM,) * n)
        self.assertEqual(report.precision, (7 * n - n) / (7 * n))
        # Low-and-slow is still missed, so not every attack is detected.
        self.assertEqual((report.attacks, report.attacks_detected), (6 * n, 5 * n))

    def test_evaluation_is_deterministic(self):
        self.assertEqual(evaluate(self.rules, self.datasets), evaluate(self.rules, self.datasets))
        self.assertEqual(simulated_dataset(7).events, simulated_dataset(7).events)

    def test_clean_benign_traffic_raises_nothing_and_the_vpn_user_raises_one(self):
        resolver = TableGeoResolver(FAKE_GEO)

        def alerts_for(kinds, seed):
            from siftlog.enrich import enrich

            sim = simulate(seed=seed, scenarios={kind: 1 for kind in kinds})
            parser = SshdParser(year=2026)
            events = [enrich(e, resolver) for n, line in enumerate(sim.lines)
                      for e in parser.parse_line(line, "benign", n).events]
            return ReplayEngine(self.rules).run(events)

        for seed in (1, 2, 3):
            self.assertEqual(alerts_for(CLEAN_BENIGN, seed), [], f"seed {seed}")
            (false_alarm,) = alerts_for(("vpn_hop",), seed)
            self.assertEqual((false_alarm.rule_id, false_alarm.group_key), ("ssh-impossible-travel", "vera"))

    # The tests below are what stop the scores above from being vacuous: if the scorer
    # could not tell a good setting from a bad one, these would fail.

    def test_brute_force_threshold_trade_off(self):
        rows = self.sweep("ssh-brute-force", [5, 10, 26, 45])
        self.assertEqual((rows[10].false_alerts, rows[10].recall), (0, 1.0))
        self.assertGreaterEqual(rows[5].false_alerts, self.N)  # the once-a-minute monitoring probe, every run
        self.assertLess(rows[5].precision, 0.8)
        self.assertEqual(rows[26].recall, 0.5)  # the 25-attempt brute force that succeeded is now missed
        self.assertEqual((rows[45].recall, rows[45].alerts), (0.0, 0))
        loose = [with_knob(r, 5) if r.id == "ssh-brute-force" else r for r in self.rules]
        self.assertIn("ssh-brute-force on 198.51.100.99", evaluate(loose, self.datasets).false_alert_details)

    def test_a_threshold_at_the_attackers_rate_makes_alerts_flap(self):
        row = self.sweep("ssh-brute-force", [3])[3]
        self.assertGreaterEqual(row.bonus_alerts, self.N)  # it does catch the low-and-slow attacker...
        self.assertGreater(row.duplicate_alerts, 10 * self.N)  # ...as a stream of alerts, not one
        self.assertEqual(row.recall, 1.0)

    def test_success_after_failures_threshold_trade_off(self):
        rows = self.sweep("ssh-success-after-failures", [1, 5, 25, 26])
        self.assertEqual((rows[5].false_alerts, rows[5].recall), (0, 1.0))
        self.assertGreaterEqual(rows[1].false_alerts, 2 * self.N)  # anyone who ever mistyped a password
        self.assertEqual(rows[25].recall, 1.0)
        self.assertEqual((rows[26].recall, rows[26].alerts), (0.0, 0))

    def test_no_speed_separates_the_vpn_user_from_the_thief(self):
        rows = self.sweep("ssh-impossible-travel", [300, 900, 5000, 50000])
        n = self.N
        self.assertEqual((rows[900].detected, rows[900].false_alerts), (n, n))
        self.assertEqual(rows[300].false_alerts, 2 * n)  # now the ordinary flight is flagged too
        self.assertEqual(rows[5000].false_alerts, n)  # still the VPN user
        self.assertEqual((rows[50000].detected, rows[50000].alerts), (0, 0))  # and now the thief is missed

    def test_knobs_name_what_they_tune(self):
        names = {rule.id: knob(rule) for rule in self.rules}
        self.assertEqual(names["ssh-brute-force"], ("threshold", 10))
        self.assertEqual(names["ssh-success-after-failures"], ("first-step threshold", 5))
        self.assertEqual(names["ssh-impossible-travel"], ("max_speed_kmh", 900.0))
        self.assertIn("raises 0 false alerts", grouping_note(self.rules, self.datasets))


if __name__ == "__main__":
    unittest.main()
