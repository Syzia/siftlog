import os
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from siftlog.engine import Alert, ReplayEngine, load_rules
from siftlog.evaluate import simulated_dataset
from siftlog.events import AUTH_FAILURE, Event
from siftlog.store import SCHEMA_VERSION, EventStore
from siftlog.store.alerts import SYSTEM_ACTOR

T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


def at(minutes):
    return T0 + timedelta(minutes=minutes)


def alert(rule="brute", key="203.0.113.1", first=0, last=10, count=10, evidence=("e0", "e1", "e2"),
          severity="high", summary=""):
    return Alert(
        id=f"{rule}/{key}/{first}", rule_id=rule, title=f"{rule} title", severity=severity, group_key=key,
        first_seen=at(first), last_seen=at(last), event_count=count, distinct_count=None,
        evidence_event_ids=tuple(evidence), evidence_truncated=False, mitre=("T1110",), summary=summary,
    )  # fmt: skip


def event(n):
    return Event(id=f"e{n}", timestamp=at(n), source="sshd", event_type=AUTH_FAILURE, src_ip="203.0.113.1",
                 username="root", host="h", outcome="failure", raw=f"line {n}", source_id="t", offset=n)


class Base(unittest.TestCase):
    def setUp(self):
        self.store = EventStore()
        self.addCleanup(self.store.close)
        self.store.add_events([event(n) for n in range(10)])

    def sync(self, alerts, rules=("brute",), now=None):
        return self.store.sync_alerts(alerts, rules, now=now)

    def counts(self, report):
        return (report.new, report.updated, report.unchanged, report.reopened, report.removed, report.superseded)


class SyncTests(Base):
    def test_new_alerts_are_stored_open_with_ordered_evidence(self):
        a = alert(evidence=("e2", "e0", "e1"))
        self.assertEqual(self.counts(self.sync([a])), (1, 0, 0, 0, 0, 0))
        stored = self.store.get_alert(a.id)
        self.assertEqual((stored.alert, stored.status, stored.note, stored.superseded, stored.status_changed_at),
                         (a, "open", "", False, None))
        self.assertEqual([e.id for e in self.store.alert_events(a.id)], ["e2", "e0", "e1"])
        self.assertEqual(self.store.list_alerts()[0].alert.evidence_event_ids, ())  # listings stay light

    def test_syncing_the_same_alerts_again_changes_nothing(self):
        a = alert()
        self.sync([a])
        before = self.store.get_alert(a.id)
        self.assertEqual(self.counts(self.sync([a])), (0, 0, 1, 0, 0, 0))
        self.assertEqual(self.store.get_alert(a.id), before)

    def test_an_alert_that_grew_is_updated_in_place(self):
        a = alert()
        self.sync([a])
        grown = replace(a, last_seen=at(30), event_count=25, evidence_event_ids=("e0", "e1", "e2", "e3"))
        self.assertEqual(self.counts(self.sync([grown])), (0, 1, 0, 0, 0, 0))
        self.assertEqual(self.store.get_alert(a.id).alert, grown)
        self.assertEqual(self.store.count_alerts(), 1)

    def test_only_the_declared_rules_are_reconciled(self):
        other = alert(rule="spray", key="203.0.113.9")
        self.sync([other], rules=("spray",))
        self.sync([alert()], rules=("brute",))
        self.sync([], rules=("brute",))  # brute now produces nothing; spray was not part of this run
        self.assertEqual([s.alert.id for s in self.store.list_alerts()], [other.id])
        with self.assertRaises(ValueError):
            self.sync([other], rules=("brute",))  # an alert from a rule that was not declared as run


class DecisionTests(Base):
    def test_a_decision_survives_a_resync(self):
        a = alert()
        self.sync([a])
        self.store.set_alert_status(a.id, "ack", note="mine", now=at(20))
        self.assertEqual(self.counts(self.sync([a])), (0, 0, 1, 0, 0, 0))
        stored = self.store.get_alert(a.id)
        self.assertEqual((stored.status, stored.note, stored.status_changed_at), ("ack", "mine", at(20)))

    def test_an_acknowledged_alert_that_grows_stays_acknowledged(self):
        a = alert()
        self.sync([a])
        self.store.set_alert_status(a.id, "ack")
        self.assertEqual(self.sync([replace(a, last_seen=at(60), event_count=99)]).reopened, 0)
        self.assertEqual(self.store.get_alert(a.id).status, "ack")

    def test_a_closed_alert_reopens_when_the_attack_carries_on(self):
        # Closing means "handled", not "muted".
        a = alert()
        self.sync([a])
        self.store.set_alert_status(a.id, "closed", note="blocked at the firewall", now=at(20))
        report = self.sync([replace(a, last_seen=at(60), event_count=99)], now=at(61))
        self.assertEqual((report.updated, report.reopened), (1, 1))
        stored = self.store.get_alert(a.id)
        self.assertEqual((stored.status, stored.status_changed_at), ("open", at(61)))
        last = self.store.alert_history(a.id)[-1]
        self.assertEqual((last.old_status, last.new_status, last.actor), ("closed", "open", SYSTEM_ACTOR))
        self.assertIn("activity continued", last.note)

    def test_a_closed_alert_stays_closed_without_new_activity(self):
        a = alert()
        self.sync([a])
        self.store.set_alert_status(a.id, "closed")
        self.assertEqual(self.sync([a]).reopened, 0)
        # A rule edit that changes the title or severity is not new activity either.
        self.assertEqual(self.sync([replace(a, severity="critical")]).reopened, 0)
        stored = self.store.get_alert(a.id)
        self.assertEqual((stored.status, stored.alert.severity), ("closed", "critical"))

    def test_status_changes_are_recorded(self):
        a = alert()
        self.sync([a])
        self.store.set_alert_status(a.id, "ack", note="looking", actor="hunter", now=at(1))
        self.store.set_alert_status(a.id, "ack", now=at(2))  # no change, no note: nothing to record
        self.store.set_alert_status(a.id, "ack", note="still looking", actor="hunter", now=at(3))
        self.store.set_alert_status(a.id, "closed", note="done", actor="hunter", now=at(4))
        self.assertEqual(
            [(h.changed_at, h.old_status, h.new_status, h.actor, h.note) for h in self.store.alert_history(a.id)],
            [(at(1), "open", "ack", "hunter", "looking"), (at(3), "ack", "ack", "hunter", "still looking"),
             (at(4), "ack", "closed", "hunter", "done")],
        )  # fmt: skip

    def test_bad_decisions_are_refused(self):
        a = alert()
        self.sync([a])
        with self.assertRaises(KeyError):
            self.store.set_alert_status("nope", "ack")
        with self.assertRaises(ValueError):
            self.store.set_alert_status(a.id, "ignored")
        self.assertEqual(self.store.get_alert(a.id).status, "open")


class NoLongerProducedTests(Base):
    """A rule was edited, and the latest replay does not produce an alert it used to."""

    def test_an_untouched_alert_is_removed_with_its_evidence(self):
        a = alert()
        self.sync([a])
        self.assertEqual(self.counts(self.sync([])), (0, 0, 0, 0, 1, 0))
        self.assertIsNone(self.store.get_alert(a.id))
        leftovers = self.store._conn.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0]
        self.assertEqual(leftovers, 0)

    def test_an_alert_someone_acted_on_is_kept_and_marked(self):
        a = alert()
        self.sync([a])
        self.store.set_alert_status(a.id, "ack", note="ticket 42")
        self.assertEqual(self.counts(self.sync([])), (0, 0, 0, 0, 0, 1))
        self.assertEqual(self.counts(self.sync([])), (0, 0, 0, 0, 0, 0))  # only counted once
        self.assertEqual(self.store.list_alerts(), [])  # hidden by default...
        (kept,) = self.store.list_alerts(include_superseded=True)  # ...but not gone
        self.assertEqual((kept.superseded, kept.status, kept.note), (True, "ack", "ticket 42"))
        self.assertEqual(self.store.count_alerts(), 0)
        self.assertEqual(self.store.count_alerts(include_superseded=True), 1)

    def test_reopened_by_hand_counts_as_acted_on(self):
        a = alert()
        self.sync([a])
        self.store.set_alert_status(a.id, "closed")
        self.store.set_alert_status(a.id, "open", note="closed by mistake")
        self.assertEqual(self.sync([]).superseded, 1)  # status is 'open', but it has a history

    def test_a_superseded_alert_comes_back_if_produced_again(self):
        a = alert()
        self.sync([a])
        self.store.set_alert_status(a.id, "ack")
        self.sync([])
        self.sync([a])
        stored = self.store.get_alert(a.id)
        self.assertEqual((stored.superseded, stored.status), (False, "ack"))


class ListingTests(Base):
    def setUp(self):
        super().setUp()
        self.a = alert(key="203.0.113.1", first=0, last=10)
        self.b = alert(key="203.0.113.2", first=20, last=30, severity="critical")
        self.c = alert(rule="spray", key="203.0.113.3", first=40, last=50)
        self.store.sync_alerts([self.a, self.b, self.c], ("brute", "spray"))
        self.store.set_alert_status(self.b.id, "ack")

    def ids(self, **filters):
        return [s.alert.id for s in self.store.list_alerts(**filters)]

    def test_newest_activity_first(self):
        self.assertEqual(self.ids(), [self.c.id, self.b.id, self.a.id])

    def test_filters(self):
        self.assertEqual(self.ids(status="ack"), [self.b.id])
        self.assertEqual(self.ids(status="open"), [self.c.id, self.a.id])
        self.assertEqual(self.ids(severity="critical"), [self.b.id])
        self.assertEqual(self.ids(rule_id="spray"), [self.c.id])
        self.assertEqual(self.ids(group_key="203.0.113.1"), [self.a.id])
        self.assertEqual(self.ids(rule_id="brute", status="open"), [self.a.id])
        self.assertEqual(self.store.count_alerts(rule_id="brute"), 2)

    def test_time_range_selects_alerts_active_in_it(self):
        self.assertEqual(self.ids(since=at(25)), [self.c.id, self.b.id])  # b was still active at minute 25
        self.assertEqual(self.ids(until=at(20)), [self.a.id])  # b starts exactly at 20: excluded
        self.assertEqual(self.ids(since=at(11), until=at(40)), [self.b.id])

    def test_paging(self):
        self.assertEqual(self.ids(limit=2), [self.c.id, self.b.id])
        self.assertEqual(self.ids(limit=2, offset=2), [self.a.id])
        with self.assertRaises(ValueError):
            self.store.list_alerts(limit=-1)

    def test_breakdowns_and_days(self):
        self.assertEqual(self.store.alert_breakdown("status"), {"ack": 1, "open": 2})
        self.assertEqual(self.store.alert_breakdown("severity"), {"critical": 1, "high": 2})
        self.assertEqual(self.store.alert_breakdown("rule_id"), {"brute": 2, "spray": 1})
        self.assertEqual(self.store.alerts_per_day(), [("2026-03-01", 3)])
        with self.assertRaises(ValueError):  # a column name can never come from a caller
            self.store.alert_breakdown("status; DROP TABLE alerts")
        self.assertEqual(self.store.count_alerts(), 3)

    def test_hostile_text_is_data(self):
        nasty = "x'; DROP TABLE alerts; --"
        d = alert(key=nasty, first=60, last=70)
        self.store.sync_alerts([self.a, self.b, d], ("brute",))
        self.store.set_alert_status(d.id, "ack", note=nasty)
        self.assertEqual(self.ids(group_key=nasty), [d.id])
        self.assertEqual(self.store.get_alert(d.id).note, nasty)
        self.assertEqual(self.ids(group_key="' OR '1'='1"), [])
        self.assertEqual(self.store.count_alerts(), 4)

    def test_evidence_that_is_no_longer_stored_is_skipped(self):
        d = alert(key="203.0.113.4", first=60, last=70, evidence=("e1", "gone", "e2"))
        self.store.sync_alerts([self.a, self.b, d], ("brute",))
        self.assertEqual([e.id for e in self.store.alert_events(d.id)], ["e1", "e2"])
        self.assertEqual(self.store.get_alert(d.id).alert.evidence_event_ids, ("e1", "gone", "e2"))


class MigrationTests(unittest.TestCase):
    def test_a_stage_4_database_is_upgraded_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            with EventStore(path) as store:
                store.add_events([event(n) for n in range(3)])
            conn = sqlite3.connect(path)  # turn it back into a version 1 database: no alert tables
            conn.executescript("DROP TABLE ingest_checkpoints; DROP TABLE alert_history; "
                               "DROP TABLE alert_events; DROP TABLE alerts; PRAGMA user_version = 1;")
            conn.close()

            with EventStore(path) as store:
                self.assertEqual(store._conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
                self.assertEqual([e.id for e in store.query()], ["e0", "e1", "e2"])  # nothing lost
                store.sync_alerts([alert()], ("brute",))
                self.assertEqual(store.count_alerts(), 1)
            with EventStore(path) as store:  # and opening it again is a no-op
                self.assertEqual(store.count_alerts(), 1)


    def test_a_stage_5_database_gains_checkpoints_and_keeps_its_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            with EventStore(path) as store:
                store.add_events([event(n) for n in range(3)])
                store.sync_alerts([alert()], ("brute",))
                store.set_alert_status(alert().id, "ack", note="kept")
            conn = sqlite3.connect(path)  # back to version 2: alerts, but no checkpoint table
            conn.executescript("DROP TABLE ingest_checkpoints; PRAGMA user_version = 2;")
            conn.close()

            with EventStore(path) as store:
                self.assertEqual(store._conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
                stored = store.get_alert(alert().id)
                self.assertEqual((stored.status, stored.note), ("ack", "kept"))
                self.assertIsNone(store.get_checkpoint("file:abc"))
                store.save_checkpoint("file:abc", "/var/log/auth.log", 120, {"parser": {"year": 2026}})
                store.save_checkpoint("file:abc", "/var/log/auth.log", 240, {"parser": {"year": 2027}})
                self.assertEqual(store.get_checkpoint("file:abc"), (240, {"parser": {"year": 2027}}))


class RealEngineTests(unittest.TestCase):
    def test_engine_alerts_round_trip_with_their_evidence(self):
        rules = load_rules(RULES_DIR)
        dataset = simulated_dataset(3)
        alerts = ReplayEngine(rules).run(dataset.events)
        with EventStore() as store:
            store.add_events(dataset.events)
            report = store.sync_alerts(alerts, [r.id for r in rules])
            self.assertEqual((report.new, len(alerts)), (7, 7))
            for a in alerts:
                self.assertEqual(store.get_alert(a.id).alert, a)
                self.assertEqual(tuple(e.id for e in store.alert_events(a.id)), a.evidence_event_ids)
            again = store.sync_alerts(ReplayEngine(rules).run(dataset.events), [r.id for r in rules])
            self.assertEqual((again.unchanged, again.new, again.updated, again.removed), (7, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
