"""Stage 1 acceptance: generated logs and real-format fixtures parse with 0 dead letters."""
import os
import unittest
from collections import Counter, defaultdict
from datetime import datetime, timezone

from siftlog.events import AUTH_FAILURE, AUTH_SUCCESS, INVALID_USER
from siftlog.ingest import iter_file_lines
from siftlog.parsers import SshdParser
from siftlog.simulator import BACKGROUND, simulate

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def parse_all(lines, year=2026):
    parser = SshdParser(year=year)
    events, ignored, dead = [], Counter(), []
    for offset, line in enumerate(lines):
        result = parser.parse_line(line, "sim", offset)
        events.extend((offset, e) for e in result.events)
        if result.ignored:
            ignored[result.ignored] += 1
        if result.dead_letter:
            dead.append(result.dead_letter)
    return events, ignored, dead


class SimulatedLogTests(unittest.TestCase):
    def test_simulated_logs_have_no_dead_letters_in_either_format(self):
        for fmt in ("syslog", "iso"):
            with self.subTest(fmt=fmt):
                sim = simulate(fmt=fmt)
                events, ignored, dead = parse_all(sim.lines)
                self.assertEqual(dead, [], dead[:3])
                self.assertGreater(len(events), 300)
                self.assertGreater(sum(ignored.values()), 300)  # PAM / session noise is understood, not dropped

    def test_syslog_and_iso_renderings_parse_to_the_same_events(self):
        # Also covers the year rollover: the window crosses 2026 -> 2027.
        start = datetime(2026, 12, 31, 12, tzinfo=timezone.utc)
        a, _, _ = parse_all(simulate(fmt="syslog", start=start).lines, year=2026)
        b, _, _ = parse_all(simulate(fmt="iso", start=start).lines)
        self.assertEqual(
            [(e.timestamp, e.event_type, e.src_ip, e.username) for _, e in a],
            [(e.timestamp, e.event_type, e.src_ip, e.username) for _, e in b],
        )
        self.assertEqual({e.timestamp.year for _, e in a}, {2026, 2027})

    def test_parsed_events_match_ground_truth_per_scenario(self):
        sim = simulate()
        events, _, _ = parse_all(sim.lines)
        by_scenario = defaultdict(list)
        for line_no, event in events:
            by_scenario[sim.line_scenarios[line_no]].append(event)

        def of(kind, event_type):
            return [e for e in by_scenario[f"{kind}-0"] if e.event_type == event_type]

        self.assertEqual(len(of("brute_force", AUTH_FAILURE)), 40)
        self.assertEqual({e.src_ip for e in of("brute_force", AUTH_FAILURE)}, {sim.labels[0].group_key})

        spray = of("password_spray", AUTH_FAILURE)
        self.assertEqual((len(spray), len({e.username for e in spray}), len({e.src_ip for e in spray})), (30, 30, 1))

        stuffing = of("credential_stuffing", AUTH_FAILURE)
        self.assertEqual(len({e.src_ip for e in stuffing}), 25)
        self.assertEqual({e.host for e in stuffing}, {"bastion01"})

        travel = of("impossible_travel", AUTH_SUCCESS)
        self.assertEqual([e.username for e in travel], ["carol", "carol"])
        self.assertEqual([e.src_ip for e in travel], ["198.51.100.10", "203.0.113.50"])

        self.assertEqual(len(of("low_and_slow", AUTH_FAILURE)), 144)
        self.assertEqual(len(of("monitor_probe", AUTH_FAILURE)), 120)
        self.assertEqual(len(of("nat_office", AUTH_SUCCESS)), 15)
        self.assertEqual(len(of("nat_office", AUTH_FAILURE)), 6)
        self.assertEqual(len(of("typo_benign", AUTH_SUCCESS)), 1)
        self.assertTrue(1 <= len(of("typo_benign", AUTH_FAILURE)) <= 3)

        # Baseline traffic is successes only: it must never look like an attack.
        self.assertEqual({e.event_type for e in by_scenario[BACKGROUND]}, {AUTH_SUCCESS})

    def test_invalid_user_lines_are_separate_from_failures(self):
        sim = simulate(scenarios={"password_spray": 1})
        events, _, _ = parse_all(sim.lines)
        kinds = Counter(e.event_type for _, e in events)
        # 29 of the 30 sprayed names are not accounts; "root" is.
        self.assertEqual((kinds[AUTH_FAILURE], kinds[INVALID_USER]), (30, 29))

    def test_ids_are_unique_within_a_file(self):
        events, _, _ = parse_all(simulate().lines)
        ids = [e.id for _, e in events]
        self.assertEqual(len(ids), len(set(ids)))


class RealFormatFixtureTests(unittest.TestCase):
    def test_fixture_parses_with_no_dead_letters(self):
        path = os.path.join(FIXTURES, "sshd_real_format.log")
        parser = SshdParser(year=2026)
        events, ignored, dead = [], Counter(), []
        for offset, line in iter_file_lines(path):
            result = parser.parse_line(line, "fixture", offset)
            events.extend(result.events)
            if result.ignored:
                ignored[result.ignored] += 1
            if result.dead_letter:
                dead.append(result.dead_letter)

        self.assertEqual(dead, [], dead)
        kinds = Counter(e.event_type for e in events)
        self.assertEqual(kinds, {AUTH_FAILURE: 9, AUTH_SUCCESS: 3, INVALID_USER: 2})
        # "message repeated 5 times" is one row carrying five failures.
        self.assertEqual(sum(e.count for e in events if e.event_type == AUTH_FAILURE), 13)
        # The hostile username line resolved to the real source address.
        hostile = [e for e in events if e.username and e.username.startswith("admin from ")]
        self.assertEqual({e.src_ip for e in hostile}, {"203.0.113.99"})
        self.assertEqual(ignored["program:CRON"], 1)
        self.assertEqual(ignored["program:sudo"], 1)
        self.assertEqual(len({e.id for e in events}), len(events))


if __name__ == "__main__":
    unittest.main()
