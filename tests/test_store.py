import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from siftlog.events import AUTH_FAILURE, AUTH_SUCCESS, DeadLetter, Event, make_event_id
from siftlog.store import SCHEMA_VERSION, EventStore, StoreError

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


def make_event(i, *, ts=None, src_ip="203.0.113.5", username="root", event_type=AUTH_FAILURE,
               count=1, extra=None, geo=None, source_id="s", offset=None):
    offset = i if offset is None else offset
    return Event(
        id=make_event_id(source_id, offset),
        timestamp=ts if ts is not None else T0 + timedelta(seconds=i),
        source="sshd",
        event_type=event_type,
        src_ip=src_ip,
        username=username,
        host="web01",
        outcome="failure",
        raw=f"raw line {i}",
        count=count,
        geo=geo,
        extra={"port": 22} if extra is None else extra,
        source_id=source_id,
        offset=offset,
    )


class RoundTripTests(unittest.TestCase):
    def test_every_field_survives_a_round_trip(self):
        e = make_event(
            1,
            ts=T0 + timedelta(microseconds=123456),
            count=5,
            geo={"country": "GB", "lat": 51.5, "lon": -0.12},
            extra={"port": 22, "invalid_user": True, "pid": None, "method": "password"},
        )
        with EventStore() as store:
            self.assertEqual(store.add_events([e]), 1)
            self.assertEqual(store.query(), [e])

    def test_none_fields_round_trip(self):
        e = make_event(1, src_ip=None, username=None)
        with EventStore() as store:
            store.add_events([e])
            self.assertEqual(store.query(), [e])

    def test_persists_across_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.db")
            events = [make_event(i) for i in range(5)]
            with EventStore(path) as store:
                store.add_events(events)
            with EventStore(path) as store:
                self.assertEqual(store.query(), events)


class IdempotencyTests(unittest.TestCase):
    def test_inserting_the_same_events_twice_changes_nothing(self):
        events = [make_event(i) for i in range(10)]
        with EventStore() as store:
            self.assertEqual(store.add_events(events), 10)
            self.assertEqual(store.add_events(events), 0)
            self.assertEqual(store.count(), 10)

    def test_a_partly_new_batch_only_adds_the_new_ones(self):
        with EventStore() as store:
            store.add_events([make_event(i) for i in range(5)])
            self.assertEqual(store.add_events([make_event(i) for i in range(3, 8)]), 3)
            self.assertEqual(store.count(), 8)

    def test_dead_letters_are_idempotent_and_ordered(self):
        letters = [DeadLetter("s", 20, "b", "why"), DeadLetter("s", 10, "a", "why")]
        with EventStore() as store:
            self.assertEqual(store.add_dead_letters(letters), 2)
            self.assertEqual(store.add_dead_letters(letters), 0)
            self.assertEqual(store.dead_letter_count(), 2)
            self.assertEqual([d.offset for d in store.dead_letters()], [10, 20])
            self.assertEqual(len(store.dead_letters(limit=1)), 1)


class QueryTests(unittest.TestCase):
    def setUp(self):
        ips = ["203.0.113.1", "203.0.113.2"]
        users = ["root", "admin", "carol"]
        self.events = [
            make_event(
                i,
                src_ip=ips[i % 2],
                username=users[i % 3],
                event_type=AUTH_SUCCESS if i % 5 == 0 else AUTH_FAILURE,
            )
            for i in range(30)
        ]
        self.store = EventStore()
        self.store.add_events(self.events)
        self.addCleanup(self.store.close)

    def ids(self, events):
        return [e.id for e in events]

    def test_filters_match_a_plain_python_filter(self):
        cases = [
            ({"src_ip": "203.0.113.1"}, lambda e: e.src_ip == "203.0.113.1"),
            ({"username": "carol"}, lambda e: e.username == "carol"),
            ({"event_type": AUTH_SUCCESS}, lambda e: e.event_type == AUTH_SUCCESS),
            ({"src_ip": "203.0.113.2", "username": "admin", "event_type": AUTH_FAILURE},
             lambda e: e.src_ip == "203.0.113.2" and e.username == "admin" and e.event_type == AUTH_FAILURE),
        ]
        for kwargs, predicate in cases:
            with self.subTest(**kwargs):
                self.assertEqual(self.ids(self.store.query(**kwargs)), self.ids(e for e in self.events if predicate(e)))
                self.assertEqual(self.store.count(**kwargs), len([e for e in self.events if predicate(e)]))

    def test_since_is_inclusive_and_until_is_exclusive(self):
        got = self.store.query(since=T0 + timedelta(seconds=2), until=T0 + timedelta(seconds=5))
        self.assertEqual([e.offset for e in got], [2, 3, 4])

    def test_adjacent_windows_partition_the_events(self):
        a = self.store.query(until=T0 + timedelta(seconds=10))
        b = self.store.query(since=T0 + timedelta(seconds=10))
        self.assertEqual(len(a) + len(b), 30)
        self.assertFalse(set(self.ids(a)) & set(self.ids(b)))

    def test_ip_and_time_window_together(self):
        since, until = T0 + timedelta(seconds=10), T0 + timedelta(seconds=20)
        got = self.store.query(src_ip="203.0.113.1", since=since, until=until)
        want = [e for e in self.events if e.src_ip == "203.0.113.1" and since <= e.timestamp < until]
        self.assertEqual(self.ids(got), self.ids(want))

    def test_limit_and_descending(self):
        self.assertEqual([e.offset for e in self.store.query(limit=3)], [0, 1, 2])
        self.assertEqual([e.offset for e in self.store.query(limit=3, descending=True)], [29, 28, 27])

    def test_bad_limits_are_rejected(self):
        for bad in (-1, "5", 1.5, True):
            with self.subTest(limit=bad), self.assertRaises(ValueError):
                self.store.query(limit=bad)

    def test_naive_datetimes_are_rejected(self):
        with self.assertRaises(ValueError):
            self.store.query(since=datetime(2026, 3, 1))

    def test_non_utc_aware_datetimes_are_converted(self):
        plus5 = timezone(timedelta(hours=5))
        got = self.store.query(since=(T0 + timedelta(seconds=28)).astimezone(plus5))
        self.assertEqual([e.offset for e in got], [28, 29])

    def test_iter_events_matches_query_across_batch_boundaries(self):
        self.assertEqual(
            self.ids(self.store.iter_events(batch_size=7)), self.ids(self.store.query())
        )

    def test_weighted_count_sums_repeat_counts(self):
        with EventStore() as store:
            store.add_events([make_event(1, count=5), make_event(2, count=1), make_event(3, count=3)])
            self.assertEqual((store.count(), store.count(weighted=True)), (3, 9))
            self.assertEqual(store.count(src_ip="198.51.100.9", weighted=True), 0)


class OrderingTests(unittest.TestCase):
    def test_events_sharing_a_timestamp_come_back_in_file_order(self):
        # Inserted in reverse: order must come from the data, not insertion order.
        same_second = [make_event(i, ts=T0, offset=i * 100) for i in range(5)]
        with EventStore() as store:
            store.add_events(reversed(same_second))
            self.assertEqual([e.offset for e in store.query()], [0, 100, 200, 300, 400])
            self.assertEqual([e.offset for e in store.query(descending=True)], [400, 300, 200, 100, 0])


class HostileInputTests(unittest.TestCase):
    def test_sql_in_log_content_is_data_not_code(self):
        nasty = "x'; DROP TABLE events; --"
        e = make_event(1, username=nasty, src_ip="203.0.113.5")
        with EventStore() as store:
            store.add_events([e])
            self.assertEqual(store.query(username=nasty), [e])
            self.assertEqual(store.query(src_ip="' OR '1'='1"), [])
            self.assertEqual(store.query(username="%"), [])  # no LIKE semantics
            self.assertEqual(store.count(), 1)  # table still there

    def test_unicode_and_control_characters_round_trip(self):
        e = make_event(1, username="‮re\x1b[31mroot�\n", extra={"k": "\u0000x"})
        with EventStore() as store:
            store.add_events([e])
            self.assertEqual(store.query(), [e])


class PlanTests(unittest.TestCase):
    def test_hot_queries_use_the_intended_indexes(self):
        with EventStore() as store:
            plan = lambda **kw: " | ".join(store.explain_query(**kw))
            self.assertIn("idx_events_src_ip_ts", plan(src_ip="203.0.113.5", since=T0))
            self.assertIn("idx_events_username_ts", plan(username="root", since=T0))
            self.assertIn("idx_events_ts", plan(since=T0, until=T0 + timedelta(hours=1)))
            for kw in ({"src_ip": "203.0.113.5"}, {"username": "root"}, {"since": T0}):
                self.assertNotIn("SCAN events", plan(**kw))


class SchemaVersionTests(unittest.TestCase):
    def test_newer_schema_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.db")
            EventStore(path).close()
            conn = sqlite3.connect(path)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
            conn.close()
            with self.assertRaises(StoreError):
                EventStore(path)

    def test_foreign_events_table_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.db")
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE events (something_else TEXT)")
            conn.commit()
            conn.close()
            with self.assertRaises(StoreError):
                EventStore(path)


if __name__ == "__main__":
    unittest.main()
