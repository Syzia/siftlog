import itertools
import unittest
from datetime import datetime, timedelta, timezone

import siftlog.engine.replay as replay_module
from siftlog.engine import ReplayEngine, parse_rule
from siftlog.engine import run_rules as replay
from siftlog.events import AUTH_FAILURE, AUTH_SUCCESS, INVALID_USER, Event

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
_ids = itertools.count()


def ev(seconds, ip="203.0.113.5", user="root", etype=AUTH_FAILURE, host="web01", count=1, geo=None):
    n = next(_ids)
    return Event(
        id=f"e{n}", timestamp=T0 + timedelta(seconds=seconds), source="sshd", event_type=etype,
        src_ip=ip, username=user, host=host, outcome="failure", raw="", count=count, geo=geo,
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


SUCCESS_AFTER_FAILURES = parse_rule({
    "id": "success", "title": "Success after failures", "type": "temporal_ordered",
    "group_by": ["src_ip", "username"], "timespan": "10m",
    "steps": [
        {"filter": {"event_type": "auth_failure"}, "condition": {"gte": 5}},
        {"filter": {"event_type": "auth_success"}},
    ],
})  # fmt: skip


def ok(seconds, **kwargs):
    return ev(seconds, etype=AUTH_SUCCESS, **kwargs)


class SequenceTests(unittest.TestCase):
    def test_failures_then_success_fires_once(self):
        events = [ev(i) for i in range(5)] + [ok(10)]
        (alert,) = replay([SUCCESS_AFTER_FAILURES], events)
        self.assertEqual((alert.rule_id, alert.group_key, alert.event_count), ("success", "203.0.113.5|root", 6))
        self.assertEqual((alert.first_seen, alert.last_seen), (at(0), at(10)))
        self.assertEqual(alert.evidence_event_ids, tuple(e.id for e in events))

    def test_too_few_failures_is_not_enough(self):
        self.assertEqual(replay([SUCCESS_AFTER_FAILURES], [ev(i) for i in range(4)] + [ok(10)]), [])

    def test_order_matters(self):
        # A login followed by failures is somebody locking themselves out, not a guessed password.
        self.assertEqual(replay([SUCCESS_AFTER_FAILURES], [ok(0)] + [ev(1 + i) for i in range(5)]), [])

    def test_failures_must_still_be_inside_the_window(self):
        failures = [ev(i) for i in range(5)]  # the last at t=4s
        self.assertEqual(len(replay([SUCCESS_AFTER_FAILURES], failures + [ok(599)])), 1)
        self.assertEqual(replay([SUCCESS_AFTER_FAILURES], [ev(i) for i in range(5)] + [ok(604)]), [])

    def test_grouping_by_user_keeps_a_shared_address_quiet(self):
        # A NAT'd office: five people mistype, a sixth logs in. Same address, different accounts.
        typos = [ev(i, ip="192.0.2.10", user=f"user{i}") for i in range(5)]
        events = typos + [ok(10, ip="192.0.2.10", user="someone-else")]
        self.assertEqual(replay([SUCCESS_AFTER_FAILURES], events), [])
        by_address_only = parse_rule({
            "id": "loose", "title": "t", "type": "temporal_ordered", "group_by": ["src_ip"], "timespan": "10m",
            "steps": [{"filter": {"event_type": "auth_failure"}, "condition": {"gte": 5}},
                      {"filter": {"event_type": "auth_success"}}],
        })  # fmt: skip
        self.assertEqual(len(replay([by_address_only], events)), 1)  # ...which is the false alarm avoided

    def test_repeat_counts_weigh_towards_a_step(self):
        self.assertEqual(len(replay([SUCCESS_AFTER_FAILURES], [ev(0, count=5), ok(5)])), 1)

    def test_a_second_login_extends_the_same_alert(self):
        (alert,) = replay([SUCCESS_AFTER_FAILURES], [ev(i) for i in range(5)] + [ok(10), ok(60)])
        self.assertEqual((alert.event_count, alert.last_seen), (7, at(60)))

    def test_only_an_event_that_completes_the_sequence_extends_the_alert(self):
        # A failure after the successful login completes nothing, so it is not evidence.
        (alert,) = replay([SUCCESS_AFTER_FAILURES], [ev(i) for i in range(5)] + [ok(10), ev(20)])
        self.assertEqual((alert.event_count, alert.last_seen), (6, at(10)))
        # ...until another success arrives, which completes it again and brings that failure with it.
        (alert,) = replay([SUCCESS_AFTER_FAILURES], [ev(i) for i in range(5)] + [ok(10), ev(20), ok(30)])
        self.assertEqual((alert.event_count, alert.last_seen), (8, at(30)))

    def test_a_much_later_login_is_unrelated(self):
        (alert,) = replay([SUCCESS_AFTER_FAILURES], [ev(i) for i in range(5)] + [ok(10), ok(5000)])
        self.assertEqual((alert.event_count, alert.last_seen), (6, at(10)))

    def test_three_steps_in_order(self):
        three = parse_rule({
            "id": "three", "title": "t", "type": "temporal_ordered", "group_by": ["src_ip"], "timespan": "10m",
            "steps": [{"filter": {"event_type": "invalid_user"}},
                      {"filter": {"event_type": "auth_failure"}, "condition": {"gte": 2}},
                      {"filter": {"event_type": "auth_success"}}],
        })  # fmt: skip
        in_order = [ev(0, etype=INVALID_USER), ev(1), ev(2), ok(3)]
        self.assertEqual(len(replay([three], in_order)), 1)
        wrong_order = [ev(0), ev(1), ev(2, etype=INVALID_USER), ok(3)]
        self.assertEqual(replay([three], wrong_order), [])

    def test_one_event_cannot_satisfy_two_steps(self):
        twice = parse_rule({
            "id": "twice", "title": "t", "type": "temporal_ordered", "group_by": ["src_ip"], "timespan": "10m",
            "steps": [{"filter": {"event_type": "auth_failure"}}, {"filter": {"event_type": "auth_failure"}}],
        })  # fmt: skip
        self.assertEqual(replay([twice], [ev(0)]), [])
        self.assertEqual(len(replay([twice], [ev(0), ev(1)])), 1)

    def test_a_successful_brute_force_trips_both_rules(self):
        events = [ev(i) for i in range(25)] + [ok(30)]
        self.assertEqual(sorted(a.rule_id for a in replay([BRUTE, SUCCESS_AFTER_FAILURES], events)), ["brute", "success"])


LONDON = {"lat": 51.5074, "lon": -0.1278, "city": "London"}
READING = {"lat": 51.4543, "lon": -0.9781, "city": "Reading"}  # about 60 km from London
NEW_YORK = {"lat": 40.7128, "lon": -74.0060, "city": "New York"}
SYDNEY = {"lat": -33.8688, "lon": 151.2093, "city": "Sydney"}
MIN = 60
HOUR = 3600


def travel(**overrides):
    data = {
        "id": "travel", "title": "Impossible travel", "type": "impossible_travel",
        "filter": {"event_type": "auth_success"}, "group_by": ["username"],
        "timespan": "24h", "max_speed_kmh": 900, "min_distance_km": 100,
    }  # fmt: skip
    data.update(overrides)
    return parse_rule(data)


def login(seconds, geo, user="carol", ip="198.51.100.10"):
    return ev(seconds, etype=AUTH_SUCCESS, user=user, ip=ip, geo=geo)


class TravelTests(unittest.TestCase):
    def test_two_distant_logins_close_in_time_fire(self):
        events = [login(0, LONDON), login(25 * MIN, SYDNEY)]
        (alert,) = replay([travel()], events)
        self.assertEqual((alert.group_key, alert.event_count), ("carol", 2))
        self.assertEqual((alert.first_seen, alert.last_seen), (at(0), at(25 * MIN)))
        self.assertEqual(alert.evidence_event_ids, tuple(e.id for e in events))
        self.assertIn("London -> Sydney", alert.summary)
        self.assertIn("km/h", alert.summary)

    def test_a_normal_flight_does_not_fire(self):
        self.assertEqual(replay([travel()], [login(0, LONDON), login(14 * HOUR, NEW_YORK)]), [])  # ~400 km/h

    def test_just_faster_than_an_airliner_fires(self):
        self.assertEqual(len(replay([travel()], [login(0, LONDON), login(5 * HOUR, NEW_YORK)])), 1)  # ~1,100 km/h

    def test_nearby_networks_are_ignored_whatever_the_speed(self):
        # GeoIP often places one user's home and mobile networks in neighbouring towns.
        hop = [login(0, LONDON), login(MIN, READING)]  # 60 km in a minute is 3,600 km/h
        self.assertEqual(replay([travel()], hop), [])
        self.assertEqual(len(replay([travel(min_distance_km=0)], hop)), 1)

    def test_same_place_twice_is_not_travel(self):
        self.assertEqual(replay([travel(min_distance_km=0)], [login(0, LONDON), login(MIN, LONDON)]), [])

    def test_users_are_independent(self):
        events = [login(0, LONDON, user="alice"), login(MIN, SYDNEY, user="bob")]
        self.assertEqual(replay([travel()], events), [])

    def test_events_without_a_location_are_skipped_not_compared(self):
        events = [login(0, LONDON), login(10 * MIN, None), login(25 * MIN, SYDNEY)]
        (alert,) = replay([travel()], events)
        self.assertEqual(alert.event_count, 2)  # London and Sydney; the unlocated login is not evidence

    def test_malformed_locations_are_ignored(self):
        bad = [{}, {"lat": 51.5}, {"lat": "51.5", "lon": "0"}, {"lat": float("nan"), "lon": 0.0},
               {"lat": 200.0, "lon": 0.0}, {"lat": True, "lon": False}, "London", 42]  # fmt: skip
        events = [login(i * MIN, geo) for i, geo in enumerate(bad)] + [login(60 * MIN, SYDNEY)]
        self.assertEqual(replay([travel()], events), [])

    def test_only_logins_inside_the_timespan_are_compared(self):
        strict = travel(timespan="1h", max_speed_kmh=1)  # anything that moves at all would fire
        self.assertEqual(len(replay([strict], [login(0, LONDON), login(30 * MIN, SYDNEY)])), 1)
        self.assertEqual(replay([strict], [login(0, LONDON), login(2 * HOUR, SYDNEY)]), [])

    def test_two_places_at_the_same_instant(self):
        (alert,) = replay([travel()], [login(0, LONDON), login(0, SYDNEY)])
        self.assertIn("at the same moment", alert.summary)

    def test_bouncing_between_two_places_is_one_alert(self):
        # The real user keeps working in London while the thief is active in Sydney.
        events = [login(0, LONDON), login(25 * MIN, SYDNEY), login(45 * MIN, LONDON)]
        (alert,) = replay([travel()], events)
        self.assertEqual((alert.event_count, alert.last_seen), (3, at(45 * MIN)))
        self.assertEqual(alert.evidence_event_ids, tuple(e.id for e in events))  # each login listed once

    def test_the_filter_still_applies(self):
        failures = [ev(0, user="carol", geo=LONDON), ev(MIN, user="carol", geo=SYDNEY)]
        self.assertEqual(replay([travel()], failures), [])


if __name__ == "__main__":
    unittest.main()
