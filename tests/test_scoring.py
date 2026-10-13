import unittest
from datetime import datetime, timedelta, timezone

from siftlog.engine import Alert, merge, score
from siftlog.simulator import ScenarioLabel

T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)


def at(minutes):
    return T0 + timedelta(minutes=minutes)


def label(id, *, attack=True, expect=True, key="203.0.113.1", rule="brute", start=0, end=10):
    return ScenarioLabel(id=id, kind=id.split("-")[0], is_attack=attack, expect_alert=expect,
                         group_key=key, rule_hint=rule if expect else None, start=at(start), end=at(end))


def alert(rule="brute", key="203.0.113.1", start=1, end=5, evidence=()):
    return Alert(id=f"{rule}-{key}-{start}", rule_id=rule, title=rule, severity="high", group_key=key,
                 first_seen=at(start), last_seen=at(end), event_count=len(evidence), distinct_count=None,
                 evidence_event_ids=tuple(evidence), evidence_truncated=False)


ATTACK = label("brute_force-0")
BENIGN = label("typo_benign-0", attack=False, expect=False, key="198.51.100.7")
QUIET = label("low_and_slow-0", expect=False, key="203.0.113.9")  # a real attack we do not expect to catch
LABELS = [ATTACK, BENIGN, QUIET]

# Ground truth for each evidence event: which scenario produced it.
TRUTH = {f"a{i}": "brute_force-0" for i in range(20)}
TRUTH.update({f"b{i}": "typo_benign-0" for i in range(20)})
TRUTH.update({f"q{i}": "low_and_slow-0" for i in range(20)})
TRUTH.update({f"g{i}": "background" for i in range(20)})


def ids(prefix, n):
    return [f"{prefix}{i}" for i in range(n)]


class EvidenceScoringTests(unittest.TestCase):
    def run_score(self, alerts, rules=("brute",)):
        return score(LABELS, alerts, rules, TRUTH)

    def test_a_correct_alert_is_full_precision_and_recall(self):
        report = self.run_score([alert(evidence=ids("a", 10))])
        row = report.rule("brute")
        self.assertEqual((row.expected, row.detected, row.alerts, row.false_alerts, row.duplicate_alerts), (1, 1, 1, 0, 0))
        self.assertEqual((report.precision, report.recall, report.missed), (1.0, 1.0, ()))

    def test_no_alert_is_a_miss(self):
        report = self.run_score([])
        self.assertEqual((report.recall, report.precision, report.missed), (0.0, None, ("brute_force-0",)))

    def test_alert_on_benign_traffic_is_false(self):
        report = self.run_score([alert(evidence=ids("a", 10)), alert(key="198.51.100.7", evidence=ids("b", 10))])
        self.assertEqual((report.rule("brute").false_alerts, report.precision, report.recall), (1, 0.5, 1.0))
        self.assertEqual(report.false_alert_details, ("brute on 198.51.100.7",))

    def test_alert_on_background_traffic_is_false(self):
        self.assertEqual(self.run_score([alert(key="198.51.100.50", evidence=ids("g", 10))]).rule("brute").false_alerts, 1)

    def test_second_alert_for_the_same_attack_is_a_duplicate_not_a_false_alarm(self):
        report = self.run_score([alert(start=1, evidence=ids("a", 10)), alert(start=6, end=9, evidence=ids("a", 10))])
        row = report.rule("brute")
        self.assertEqual((row.alerts, row.duplicate_alerts, row.false_alerts, row.precision), (2, 1, 0, 1.0))

    def test_catching_an_unexpected_attack_is_a_bonus_not_a_false_alarm(self):
        report = self.run_score([alert(key="203.0.113.9", evidence=ids("q", 10))])
        row = report.rule("brute")
        self.assertEqual((row.bonus_alerts, row.false_alerts, row.precision), (1, 0, 1.0))
        self.assertEqual(report.recall, 0.0)  # the attack we were supposed to catch is still missed

    def test_mixed_evidence_is_decided_by_the_majority(self):
        mostly_attack = alert(evidence=ids("a", 6) + ids("b", 4))
        mostly_benign = alert(evidence=ids("a", 4) + ids("b", 6))
        self.assertEqual(self.run_score([mostly_attack]).rule("brute").false_alerts, 0)
        self.assertEqual(self.run_score([mostly_benign]).rule("brute").false_alerts, 1)

    def test_detection_needs_the_right_rule_and_group(self):
        wrong_rule = self.run_score([alert(rule="spray", evidence=ids("a", 10))], rules=("brute", "spray"))
        self.assertEqual((wrong_rule.recall, wrong_rule.rule("spray").bonus_alerts), (0.0, 1))
        wrong_group = self.run_score([alert(key="web01", evidence=ids("a", 10))])
        self.assertEqual(wrong_group.recall, 0.0)

    def test_expected_rule_that_was_not_run_is_shown_as_missing(self):
        report = score(LABELS, [], rule_ids=("spray",), event_scenarios=TRUTH)
        row = report.rule("brute")
        self.assertEqual((row.loaded, row.expected, row.detected, row.recall), (False, 1, 0, 0.0))
        self.assertIn("not implemented", report.to_markdown())

    def test_attack_recall_counts_documented_misses_against_us(self):
        report = self.run_score([alert(evidence=ids("a", 10))])
        self.assertEqual((report.attacks, report.documented_misses), (2, ("low_and_slow-0",)))
        self.assertEqual((report.recall, report.attack_recall), (1.0, 0.5))


class FallbackScoringTests(unittest.TestCase):
    """Without per-event ground truth, matching is by group key and time overlap."""

    def test_group_and_time_overlap(self):
        self.assertEqual(score(LABELS, [alert()], ("brute",)).recall, 1.0)
        outside = score(LABELS, [alert(start=30, end=40)], ("brute",))
        self.assertEqual((outside.recall, outside.rule("brute").false_alerts), (0.0, 1))
        self.assertEqual(score(LABELS, [alert(key="198.51.100.7")], ("brute",)).rule("brute").false_alerts, 1)


class MergeAndReportTests(unittest.TestCase):
    def test_merge_adds_runs_together(self):
        good = score(LABELS, [alert(evidence=ids("a", 10))], ("brute",), TRUTH)
        bad = score(LABELS, [alert(key="198.51.100.7", evidence=ids("b", 10))], ("brute",), TRUTH)
        total = merge([good, bad])
        row = total.rule("brute")
        self.assertEqual((row.expected, row.detected, row.alerts, row.false_alerts), (2, 1, 2, 1))
        self.assertEqual((total.precision, total.recall, total.attacks), (0.5, 0.5, 4))
        self.assertEqual(total.missed, ("brute_force-0",))

    def test_markdown_has_a_row_per_rule_and_a_total(self):
        text = score(LABELS, [alert(evidence=ids("a", 10))], ("brute",), TRUTH).to_markdown()
        self.assertIn("| `brute` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% |", text)
        self.assertIn("| **All** |", text)
        self.assertIn("50.0% of all attacks", text)


if __name__ == "__main__":
    unittest.main()
