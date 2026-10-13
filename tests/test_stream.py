import itertools
import os
import random
import unittest
from datetime import datetime, timedelta, timezone

from siftlog.engine import ReorderBuffer, ReplayEngine, StreamingEngine, load_rules, parse_rule
from siftlog.evaluate import simulated_dataset
from siftlog.events import AUTH_FAILURE, Event

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
_ids = itertools.count()

BRUTE = parse_rule({
    "id": "brute", "title": "Brute force", "type": "event_count",
    "filter": {"event_type": "auth_failure"}, "group_by": ["src_ip"],
    "timespan": "5m", "condition": {"gte": 10},
})  # fmt: skip


def ev(seconds, ip="203.0.113.5", source_id="t"):
    n = next(_ids)
    return Event(id=f"s{n}", timestamp=T0 + timedelta(seconds=seconds), source="sshd", event_type=AUTH_FAILURE,
                 src_ip=ip, username="root", host="web01", outcome="failure", raw="", source_id=source_id, offset=n)


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def stream(rules, chunks, **kwargs):
    """Feed chunks in turn and return (final alerts, the engine)."""
    engine = StreamingEngine(rules, **kwargs)
    seen = {}
    for chunk in chunks:
        for alert in engine.feed(chunk):
            seen[alert.id] = alert
    for alert in engine.open_alerts():
        seen[alert.id] = alert
    return sorted(seen.values(), key=lambda a: (a.first_seen, a.rule_id, a.group_key)), engine


class EquivalenceTests(unittest.TestCase):
    def test_streaming_in_any_chunking_ends_where_replay_does(self):
        rules = load_rules(RULES_DIR)
        for seed in (1, 2, 3):
            events = simulated_dataset(seed).events
            expected = ReplayEngine(rules).run(events)
            self.assertEqual(len(expected), 7)
            rng = random.Random(seed)
            for name, size in (("one at a time", lambda: 1), ("random", lambda: rng.randint(1, 60)), ("all at once", lambda: 10**9)):
                chunks, i = [], 0
                while i < len(events):
                    n = size()
                    chunks.append(events[i:i + n])
                    i += n
                with self.subTest(seed=seed, chunking=name):
                    self.assertEqual(stream(rules, chunks)[0], expected)


class LiveAlertTests(unittest.TestCase):
    def test_alert_is_reported_while_the_attack_is_still_running(self):
        engine = StreamingEngine([BRUTE])
        self.assertEqual(engine.feed([ev(i) for i in range(9)]), [])
        (opened,) = engine.feed([ev(9)])  # the tenth failure
        self.assertEqual((opened.event_count, opened.first_seen, opened.last_seen), (10, at(0), at(9)))
        (grown,) = engine.feed([ev(10 + i) for i in range(5)])
        self.assertEqual((grown.id, grown.event_count, grown.last_seen), (opened.id, 15, at(14)))
        self.assertEqual(engine.feed([]), [])  # nothing new, nothing to report
        self.assertEqual(engine.open_alerts(), [grown])

    def test_a_later_burst_is_a_new_alert_and_the_old_one_is_closed(self):
        engine = StreamingEngine([BRUTE])
        (first,) = engine.feed([ev(i) for i in range(10)])
        changed = engine.feed([ev(3600 + i) for i in range(10)])
        self.assertEqual([a.first_seen for a in changed], [at(0), at(3600)])
        self.assertEqual(changed[0], first)  # closed exactly as last reported
        self.assertEqual([a.first_seen for a in engine.open_alerts()], [at(3600)])

    def test_quiet_groups_are_forgotten(self):
        engine = StreamingEngine([BRUTE])
        engine.feed([ev(i, ip=f"203.0.113.{i}") for i in range(1, 30)])
        self.assertEqual(engine.tracked_groups, 29)
        engine.feed([ev(7200, ip="198.51.100.1")])  # two hours on, the earlier addresses are long idle
        self.assertEqual(engine.tracked_groups, 1)

    def test_duplicate_rule_ids_are_refused(self):
        with self.assertRaises(ValueError):
            StreamingEngine([BRUTE, BRUTE])


class OrderingTests(unittest.TestCase):
    def test_disorder_within_one_feed_is_sorted_out(self):
        events = [ev(i) for i in range(10)]
        engine = StreamingEngine([BRUTE])
        (alert,) = engine.feed(list(reversed(events)))
        self.assertEqual((alert.event_count, alert.evidence_event_ids, engine.late_events),
                         (10, tuple(e.id for e in events), 0))

    def test_an_event_older_than_what_was_processed_is_skipped_and_counted(self):
        engine = StreamingEngine([BRUTE])
        engine.feed([ev(100 + i) for i in range(9)])
        self.assertEqual(engine.feed([ev(50)]), [])  # would have been the tenth, but it is 50s in the past
        self.assertEqual(engine.late_events, 1)
        self.assertEqual(len(engine.feed([ev(200)])), 1)  # an in-order one still completes the ten

    def test_reorder_buffer_holds_then_releases_in_time_order(self):
        clock = [0.0]
        buffer = ReorderBuffer(2.0, clock=lambda: clock[0])
        late_arrival, early_arrival = ev(5), ev(10)
        buffer.add([early_arrival])
        clock[0] = 1.0
        buffer.add([late_arrival])  # happened first, arrived second
        self.assertEqual(buffer.release(), [])
        clock[0] = 2.0
        self.assertEqual(buffer.release(), [early_arrival])  # waited its two seconds
        clock[0] = 3.0
        self.assertEqual((buffer.release(), len(buffer)), ([late_arrival], 0))

    def test_stragglers_inside_the_wait_are_put_back_in_order(self):
        clock = [0.0]
        buffer = ReorderBuffer(2.0, clock=lambda: clock[0])
        a, b = ev(10), ev(5)
        buffer.add([a])
        clock[0] = 0.5
        buffer.add([b])
        clock[0] = 2.5
        self.assertEqual(buffer.release(), [b, a])

    def test_no_wait_and_drain(self):
        buffer = ReorderBuffer(0.0)
        a, b = ev(2), ev(1)
        buffer.add([a, b])
        self.assertEqual(buffer.release(), [b, a])
        held = ReorderBuffer(60.0)
        held.add([a, b])
        self.assertEqual((held.release(), held.drain(), len(held)), ([], [b, a], 0))
        with self.assertRaises(ValueError):
            ReorderBuffer(-1)


class BoundedStateTests(unittest.TestCase):
    def test_tracked_groups_never_exceed_the_cap(self):
        engine = StreamingEngine([BRUTE], max_groups=3)
        engine.feed([ev(i, ip=f"203.0.113.{i}") for i in range(10)])  # ten addresses, one failure each
        self.assertEqual((engine.tracked_groups, engine.evicted_groups), (3, 7))

    def test_an_open_alert_is_closed_not_lost_when_its_group_is_evicted(self):
        engine = StreamingEngine([BRUTE], max_groups=2)
        (opened,) = engine.feed([ev(i) for i in range(10)])
        changed = engine.feed([ev(20, ip="198.51.100.1"), ev(21, ip="198.51.100.2")])
        self.assertEqual(changed, [opened])
        self.assertEqual(engine.open_alerts(), [])

    def test_the_cap_is_a_trade_off_and_it_is_visible(self):
        # Nine failures, then enough other addresses to push the attacker out, then a tenth.
        noise = [ev(20 + i, ip=f"198.51.100.{i}") for i in range(5)]
        events = [ev(i) for i in range(9)] + noise + [ev(30)]
        self.assertEqual(len(ReplayEngine([BRUTE]).run(events)), 1)
        capped = ReplayEngine([BRUTE], max_groups=3)
        self.assertEqual(capped.run(events), [])  # the first nine were forgotten
        self.assertGreater(capped.evicted_groups, 0)  # ...and the engine says so

    def test_recently_active_groups_are_the_ones_kept(self):
        engine = StreamingEngine([BRUTE], max_groups=2)
        engine.feed([ev(0, ip="203.0.113.1"), ev(1, ip="203.0.113.2"), ev(2, ip="203.0.113.1"),
                     ev(3, ip="203.0.113.3")])  # fmt: skip
        self.assertEqual(engine.evicted_groups, 1)
        # .1 was active more recently than .2, so .2 went: nine more from .1 complete its ten.
        self.assertEqual(len(engine.feed([ev(4 + i, ip="203.0.113.1") for i in range(8)])), 1)


if __name__ == "__main__":
    unittest.main()
