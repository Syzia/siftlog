"""Stage 3 acceptance: every attack scenario fires exactly one alert, benign traffic fires none.

Measured through the real pipeline (simulator -> log file -> parser -> SQLite
store -> replay engine) and scored against the simulator's ground truth.
"""
import contextlib
import io
import os
import tempfile
import unittest
from dataclasses import replace

from siftlog.engine import ReplayEngine, load_rules, score
from siftlog.engine.__main__ import main as engine_cli
from siftlog.evaluate import evaluate, file_event_scenarios, simulated_dataset, threshold_sweep
from siftlog.ingest import ingest_file
from siftlog.parsers import SshdParser
from siftlog.simulator import load_labels, simulate, write_files
from siftlog.store import EventStore

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
IMPLEMENTED = ("ssh-brute-force", "ssh-credential-stuffing", "ssh-password-spray")
BENIGN = ("typo_benign", "nat_office", "legit_travel", "monitor_probe")


class EndToEndFileTests(unittest.TestCase):
    def test_log_file_to_scored_alerts(self):
        rules = load_rules(RULES_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            log, labels_path, db = (os.path.join(tmp, n) for n in ("sim.log", "sim.labels.json", "events.db"))
            write_files(simulate(seed=1234), log, labels_path)
            with EventStore(db) as store:
                self.assertEqual(ingest_file(log, SshdParser(year=2026), store).dead_letters, 0)
                alerts = ReplayEngine(rules).run(store.iter_events())
                stored_ids = {e.id for e in store.iter_events()}

            labels = {label.kind: label for label in load_labels(labels_path)}
            # Exactly one alert per implemented attack, keyed on what the label says.
            self.assertEqual(
                sorted((a.rule_id, a.group_key) for a in alerts),
                sorted((labels[k].rule_hint, labels[k].group_key)
                       for k in ("brute_force", "password_spray", "credential_stuffing")),
            )
            for a in alerts:  # every alert links back to real stored events
                self.assertTrue(a.evidence_event_ids)
                self.assertTrue(set(a.evidence_event_ids) <= stored_ids)

            truth = file_event_scenarios(log, labels_path)
            report = score(list(labels.values()), alerts, [r.id for r in rules], truth)
            for rule_id in IMPLEMENTED:
                row = report.rule(rule_id)
                self.assertEqual((row.expected, row.detected, row.alerts, row.false_alerts, row.duplicate_alerts),
                                 (1, 1, 1, 0, 0), rule_id)
            # Honest about the gaps: the travel rule is stage 4, low-and-slow is a documented miss.
            self.assertEqual(report.missed, ("impossible_travel-0",))
            self.assertEqual(report.documented_misses, ("low_and_slow-0",))
            self.assertFalse(report.rule("ssh-impossible-travel").loaded)

            # The CLI gives the same answer from the same database.
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                engine_cli(["--db", db, "--rules", RULES_DIR, "--labels", labels_path, "--log", log])
            self.assertIn("3 alert(s) from 3 rule(s)", out.getvalue())
            self.assertIn("| `ssh-brute-force` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% |", out.getvalue())


class ManySeedTests(unittest.TestCase):
    SEEDS = range(1, 21)

    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(RULES_DIR)
        cls.datasets = [simulated_dataset(seed) for seed in cls.SEEDS]

    def test_every_implemented_rule_is_exact_across_seeds(self):
        report = evaluate(self.rules, self.datasets)
        for rule_id in IMPLEMENTED:
            row = report.rule(rule_id)
            self.assertEqual(
                (row.expected, row.detected, row.alerts, row.false_alerts, row.duplicate_alerts, row.bonus_alerts),
                (20, 20, 20, 0, 0, 0), rule_id,
            )
        self.assertEqual(report.false_alert_details, ())
        self.assertEqual(report.precision, 1.0)
        # Overall recall is NOT 100%: impossible travel has no rule yet.
        self.assertEqual(report.recall, 0.75)
        self.assertEqual(report.attack_recall, 0.6)  # 3 of 5 attack kinds, counting low-and-slow

    def test_evaluation_is_deterministic(self):
        self.assertEqual(evaluate(self.rules, self.datasets), evaluate(self.rules, self.datasets))
        self.assertEqual(simulated_dataset(7).events, simulated_dataset(7).events)

    def test_benign_only_traffic_raises_nothing(self):
        for seed in (1, 2, 3):
            sim = simulate(seed=seed, scenarios={kind: 1 for kind in BENIGN})
            events = []
            parser = SshdParser(year=2026)
            for n, line in enumerate(sim.lines):
                events.extend(parser.parse_line(line, "benign", n).events)
            self.assertEqual(ReplayEngine(self.rules).run(events), [], f"seed {seed}")

    # The three tests below are what stop the scores above from being vacuous: if the
    # scorer could not tell good thresholds from bad ones, these would fail.

    def test_too_low_a_threshold_costs_precision(self):
        rows = dict(threshold_sweep(self.rules, "ssh-brute-force", [5, 10], self.datasets))
        self.assertEqual(rows[10].false_alerts, 0)
        self.assertGreaterEqual(rows[5].false_alerts, 20)  # the once-a-minute monitoring probe, every seed
        self.assertLess(rows[5].precision, 0.75)
        self.assertEqual(rows[5].recall, 1.0)
        loose = [replace(r, threshold=5) if r.id == "ssh-brute-force" else r for r in self.rules]
        self.assertIn("ssh-brute-force on 198.51.100.99", evaluate(loose, self.datasets).false_alert_details)

    def test_too_high_a_threshold_costs_recall(self):
        rows = dict(threshold_sweep(self.rules, "ssh-brute-force", [40, 45], self.datasets))
        self.assertEqual(rows[40].recall, 1.0)  # the simulated brute force is exactly 40 attempts
        self.assertEqual((rows[45].recall, rows[45].alerts), (0.0, 0))

    def test_a_threshold_at_the_attackers_rate_makes_alerts_flap(self):
        # At 3-per-5-minutes the rule catches the low-and-slow attacker (a bonus), but the
        # condition keeps lapsing and re-firing: one attack becomes many alerts.
        row = dict(threshold_sweep(self.rules, "ssh-brute-force", [3], self.datasets))[3]
        self.assertGreaterEqual(row.bonus_alerts, 20)
        self.assertGreater(row.duplicate_alerts, 10 * 20)
        self.assertEqual(row.recall, 1.0)


if __name__ == "__main__":
    unittest.main()
