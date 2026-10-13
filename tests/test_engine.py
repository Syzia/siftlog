import itertools
import unittest
from datetime import datetime, timedelta, timezone

import siftlog.engine.replay as replay_module
from siftlog.engine import ReplayEngine, parse_rule
from siftlog.engine import run_rules as replay
from siftlog.events import AUTH_FAILURE, AUTH_SUCCESS, INVALID_USER, Event

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
_ids = itertools.count()


def ev(seconds, ip="203.0.113.5", user="root", etype=AUTH_FAILURE, host="web01", count=1):
    n = next(_ids)
    return Event(
        id=f"e{n}", timestamp=T0 + timedelta(seconds=seconds), source="sshd", event_type=etype,
        src_ip=ip, username=user, host=host, outcome="failure", raw="", count=count,
        source_id="t", offset=n,
    )  # fmt: skip


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def rule(**overrides):
    data = {
        "id": "brute", "title": "Brute force", "type": "event_count",
        "filter": {"event_type": "auth_failure"}, "group_by": ["src_ip"],
        "timespan": "5m", "condition": {"gte": 10},
    }  # fmt: skip
    data.update(overrides)
    return parse_rule(data)


BRUTE = rule()
SPRAY = rule(id="spray", type="value_count", distinct="username", timespan="10m", condition={"gte": 8})
STUFFING = rule(id="stuffing", type="value_count", group_by=["host"], distinct="src_ip",
                timespan="10m", condition={"gte": 15})


class EventCountTests(unittest.TestCase):
    def test_fires_at_the_threshold_and_not_below(self):
        self.assertEqual(replay([BRUTE], [ev(i) for i in range(9)]), [])
        events = [ev(i) for i in range(10)]
        (alert,) = replay([BRUTE], events)
        self.assertEqual((alert.rule_id, alert.group_key, alert.event_count), ("brute", "203.0.113.5", 10))
        self.assertEqual((alert.first_seen, alert.last_seen), (at(0), at(9)))
        self.assertEqual(alert.evidence_event_ids, tuple(e.id for e in events))
        self.assertIsNone(alert.distinct_count)
        self.assertFalse(alert.evidence_truncated)

    def test_one_attack_is_one_alert_however_long_it_runs(self):
        (alert,) = replay([BRUTE], [ev(i) for i in range(500)])
        self.assertEqual((alert.event_count, alert.first_seen, alert.last_seen), (500, at(0), at(499)))

    def test_attack_straddling_a_fixed_bucket_boundary_is_caught(self):
        # 9 failures just before 5:00 and 9 just after. Fixed 5-minute buckets see 9 and 9
        # and never fire; a sliding window sees 18 inside 20 seconds.
        events = [ev(291 + i) for i in range(9)] + [ev(301 + i) for i in range(9)]
        (alert,) = replay([BRUTE], events)
        self.assertEqual(alert.event_count, 18)

    def test_window_excludes_events_exactly_one_timespan_old(self):
        nine = [ev(i) for i in range(9)]
        self.assertEqual(len(replay([BRUTE], nine + [ev(299)])), 1)  # 299s after the first: inside
        self.assertEqual(replay([BRUTE], [ev(i) for i in range(9)] + [ev(300)]), [])  # exactly 300s: outside

    def test_repeat_counts_are_summed_not_rows(self):
        # "message repeated 5 times" is one row standing for five attempts.
        events = [ev(0, count=5)] + [ev(1 + i) for i in range(5)]
        (alert,) = replay([BRUTE], events)
        self.assertEqual((alert.event_count, len(alert.evidence_event_ids)), (10, 6))

    def test_groups_are_independent(self):
        both_under = [ev(i, ip="203.0.113.1") for i in range(9)] + [ev(i, ip="203.0.113.2") for i in range(9)]
        self.assertEqual(replay([BRUTE], sorted(both_under, key=lambda e: e.timestamp)), [])
        mixed = [ev(i, ip="203.0.113.1") for i in range(10)] + [ev(i, ip="203.0.113.2") for i in range(3)]
        (alert,) = replay([BRUTE], sorted(mixed, key=lambda e: e.timestamp))
        self.assertEqual(alert.group_key, "203.0.113.1")

    def test_filter_decides_what_counts(self):
        successes = [ev(i, etype=AUTH_SUCCESS) for i in range(50)]
        self.assertEqual(replay([BRUTE], successes), [])
        both = rule(filter={"event_type": ["auth_failure", "invalid_user"]})
        mixed = [ev(i, etype=AUTH_FAILURE if i % 2 else INVALID_USER) for i in range(10)]
        self.assertEqual(len(replay([both], mixed)), 1)
        self.assertEqual(replay([BRUTE], mixed), [])  # only 5 of them are auth_failure

    def test_gt_needs_one_more_than_gte(self):
        strictly_more = rule(condition={"gt": 10})
        self.assertEqual(replay([strictly_more], [ev(i) for i in range(10)]), [])
        self.assertEqual(len(replay([strictly_more], [ev(i) for i in range(11)])), 1)

    def test_events_without_the_group_field_are_skipped(self):
        self.assertEqual(replay([BRUTE], [ev(i, ip=None) for i in range(50)]), [])


class EpisodeTests(unittest.TestCase):
    def test_a_later_burst_is_a_new_alert(self):
        events = [ev(i) for i in range(10)] + [ev(3600 + i) for i in range(10)]
        first, second = replay([BRUTE], events)
        self.assertEqual((first.first_seen, second.first_seen), (at(0), at(3600)))
        self.assertNotEqual(first.id, second.id)
        self.assertEqual((first.event_count, second.event_count), (10, 10))

    def test_a_brief_dip_inside_the_cooldown_stays_one_alert(self):
        # Burst, then the condition lapses as the window empties, then a second burst
        # arrives before the cooldown (5m after the condition last held at t=9s) is up.
        events = [ev(i) for i in range(10)] + [ev(305 + i / 10) for i in range(10)]
        (alert,) = replay([BRUTE], events)
        self.assertEqual((alert.first_seen, alert.last_seen), (at(0), at(305.9)))
        self.assertEqual(alert.event_count, 20)  # the events during the dip are counted once it resumes
        self.assertEqual(len(set(alert.evidence_event_ids)), 20)

    def test_the_same_second_burst_after_the_cooldown_splits(self):
        events = [ev(i) for i in range(10)] + [ev(400 + i / 10) for i in range(10)]
        self.assertEqual(len(replay([BRUTE], events)), 2)

    def test_last_seen_is_when_the_condition_last_held(self):
        # Trailing events keep the alert alive only while the window still holds 10.
        events = [ev(i) for i in range(10)] + [ev(100), ev(200), ev(320), ev(700)]
        (alert,) = replay([BRUTE], events)
        self.assertEqual((alert.last_seen, alert.event_count), (at(200), 12))

    def test_host_level_alert_closes_even_though_failures_never_stop(self):
        # Regression for a design flaw: "the alert stays open while matching events keep
        # arriving" never closes for a rule grouped by host, because an internet-facing
        # host always has failures. It would swallow every later stuffing attack.
        def burst(start):
            return [ev(start + i, ip=f"203.0.113.{i + 1}", user=f"u{i}") for i in range(15)]

        noise = [ev(60 * m, ip="198.51.100.99", user="nagios") for m in range(1, 240)]
        events = sorted(burst(0) + noise + burst(7200), key=lambda e: e.timestamp)
        first, second = replay([STUFFING], events)
        self.assertEqual((first.group_key, second.group_key), ("web01", "web01"))
        self.assertEqual(first.last_seen, at(600))  # the last moment 15 sources were inside 10 minutes
        self.assertEqual(second.first_seen, at(6660))  # earliest event in the window that re-triggered
        self.assertGreaterEqual(second.distinct_count, 15)


class ValueCountTests(unittest.TestCase):
    def test_counts_distinct_values_not_events(self):
        hammering_one_user = [ev(i, user="root") for i in range(100)]
        self.assertEqual(replay([SPRAY], hammering_one_user), [])
        spray = [ev(i * 30, user=f"user{i}") for i in range(8)]
        (alert,) = replay([SPRAY], spray)
        self.assertEqual((alert.distinct_count, alert.event_count, alert.group_key), (8, 8, "203.0.113.5"))

    def test_distinct_values_age_out_of_the_window(self):
        # 8 usernames, but spread so that no 10-minute window ever holds 8 of them.
        slow = [ev(i * 100, user=f"user{i}") for i in range(8)]
        self.assertEqual(replay([SPRAY], slow), [])

    def test_repeats_inside_the_window_do_not_inflate_the_count(self):
        events = [ev(i, user=f"user{i % 7}") for i in range(70)]
        self.assertEqual(replay([SPRAY], events), [])

    def test_events_missing_the_counted_field_are_skipped(self):
        self.assertEqual(replay([SPRAY], [ev(i, user=None) for i in range(50)]), [])

    def test_distinct_count_covers_the_whole_episode(self):
        (alert,) = replay([SPRAY], [ev(i * 20, user=f"user{i}") for i in range(30)])
        self.assertEqual((alert.distinct_count, alert.event_count), (30, 30))


class EngineContractTests(unittest.TestCase):
    def mixed(self):
        events = (
            [ev(i, ip="203.0.113.1") for i in range(30)]
            # 40s apart: at most 8 in any 5 minutes, so a spray and not a brute force
            + [ev(50 + i * 40, ip="203.0.113.2", user=f"user{i}") for i in range(20)]
            + [ev(2000 + i, ip="203.0.113.3") for i in range(12)]
        )
        return sorted(events, key=lambda e: (e.timestamp, e.offset))

    def test_replay_is_deterministic_and_sorted(self):
        events = self.mixed()
        a, b = replay([BRUTE, SPRAY], events), replay([SPRAY, BRUTE], events)
        self.assertEqual(a, b)  # same alerts, same ids, whatever order the rules are given in
        self.assertEqual([x.first_seen for x in a], sorted(x.first_seen for x in a))
        self.assertEqual({(x.rule_id, x.group_key) for x in a},
                         {("brute", "203.0.113.1"), ("spray", "203.0.113.2"), ("brute", "203.0.113.3")})

    def test_out_of_order_events_are_refused(self):
        with self.assertRaises(ValueError):
            replay([BRUTE], [ev(10), ev(5)])

    def test_evidence_list_is_capped_but_counts_stay_exact(self):
        (alert,) = ReplayEngine([BRUTE], max_evidence=5).run([ev(i) for i in range(50)])
        self.assertEqual((len(alert.evidence_event_ids), alert.evidence_truncated, alert.event_count), (5, True, 50))

    def test_duplicate_rule_ids_are_refused(self):
        with self.assertRaises(ValueError):
            ReplayEngine([BRUTE, rule()])

    def test_dropping_idle_groups_does_not_change_the_result(self):
        events = self.mixed() + [ev(90000 + i, ip="203.0.113.1") for i in range(10)]
        expected = replay([BRUTE, SPRAY, STUFFING], events)
        original = replay_module._SWEEP_EVERY
        replay_module._SWEEP_EVERY = 3  # sweep constantly instead of every 20,000 events
        try:
            self.assertEqual(replay([BRUTE, SPRAY, STUFFING], events), expected)
        finally:
            replay_module._SWEEP_EVERY = original
        self.assertEqual(len([a for a in expected if a.group_key == "203.0.113.1"]), 2)


if __name__ == "__main__":
    unittest.main()
