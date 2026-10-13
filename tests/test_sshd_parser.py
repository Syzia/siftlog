import unittest
from datetime import datetime, timedelta, timezone

from siftlog.events import AUTH_FAILURE, AUTH_SUCCESS, INVALID_USER, Event, make_event_id
from siftlog.parsers import SshdParser

UTC = timezone.utc


def parse_one(line, year=2026, tz=UTC, offset=0):
    return SshdParser(year=year, tz=tz).parse_line(line, "test", offset)


def only_event(test, result):
    test.assertIsNone(result.dead_letter, result.dead_letter)
    test.assertIsNone(result.ignored)
    test.assertEqual(len(result.events), 1)
    return result.events[0]


class EventSchemaTests(unittest.TestCase):
    def test_rejects_naive_and_non_utc_timestamps(self):
        for ts in (datetime(2026, 1, 1), datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2)))):
            with self.assertRaises(ValueError):
                Event(id="x", timestamp=ts, source="s", event_type="t", src_ip=None,
                      username=None, host=None, outcome=None, raw="")

    def test_event_id_is_deterministic_and_position_based(self):
        self.assertEqual(make_event_id("f", 10), make_event_id("f", 10))
        self.assertNotEqual(make_event_id("f", 10), make_event_id("f", 11))
        self.assertNotEqual(make_event_id("f", 10), make_event_id("g", 10))


class EventParsingTests(unittest.TestCase):
    def test_failed_password_valid_user(self):
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[4242]: Failed password for root from 203.0.113.5 port 51234 ssh2"))
        self.assertEqual(
            (e.event_type, e.outcome, e.src_ip, e.username, e.host, e.count),
            (AUTH_FAILURE, "failure", "203.0.113.5", "root", "web01", 1),
        )
        self.assertEqual(e.timestamp, datetime(2026, 10, 13, 11, 16, 2, tzinfo=UTC))
        self.assertEqual((e.extra["port"], e.extra["pid"], e.extra["method"]), (51234, 4242, "password"))
        self.assertFalse(e.extra["invalid_user"])

    def test_failed_password_invalid_user(self):
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: Failed password for invalid user oracle from 203.0.113.5 port 22 ssh2"))
        self.assertEqual((e.event_type, e.username), (AUTH_FAILURE, "oracle"))
        self.assertTrue(e.extra["invalid_user"])

    def test_accepted_publickey_with_fingerprint_tail(self):
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: Accepted publickey for deploy from 198.51.100.12 port 50122 ssh2: RSA SHA256:abc"))
        self.assertEqual((e.event_type, e.outcome, e.username), (AUTH_SUCCESS, "success", "deploy"))
        self.assertEqual(e.extra["method"], "publickey")

    def test_invalid_user_line_is_its_own_type_without_outcome(self):
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: Invalid user admin from 203.0.113.5 port 41022"))
        self.assertEqual((e.event_type, e.outcome, e.username), (INVALID_USER, None, "admin"))

    def test_invalid_user_line_without_port_older_openssh(self):
        e = only_event(self, parse_one("Oct 13 11:16:02 web01 sshd[1]: Invalid user admin from 203.0.113.5"))
        self.assertEqual(e.src_ip, "203.0.113.5")
        self.assertNotIn("port", e.extra)

    def test_hostile_username_cannot_spoof_the_source_ip(self):
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: Failed password for invalid user admin from 192.0.2.9 port 1 "
            "from 203.0.113.99 port 52000 ssh2"))
        self.assertEqual(e.src_ip, "203.0.113.99")
        self.assertEqual(e.username, "admin from 192.0.2.9 port 1")
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: Invalid user admin from 192.0.2.9 port 1 from 203.0.113.99 port 52000"))
        self.assertEqual((e.src_ip, e.extra["port"]), ("203.0.113.99", 52000))

    def test_username_containing_a_complete_fake_tail_cannot_spoof_the_source_ip(self):
        # The harder case: the username itself ends in "from <ip> port <n> ssh2".
        # Only an end-anchored pattern with a greedy user group takes the real, last one.
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: Failed password for invalid user x from 192.0.2.9 port 1 ssh2 "
            "from 203.0.113.99 port 52000 ssh2"))
        self.assertEqual((e.src_ip, e.extra["port"]), ("203.0.113.99", 52000))
        self.assertEqual(e.username, "x from 192.0.2.9 port 1 ssh2")

    def test_message_repeated_carries_count(self):
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: message repeated 5 times: "
            "[ Failed password for root from 203.0.113.5 port 22 ssh2]"))
        self.assertEqual((e.event_type, e.count), (AUTH_FAILURE, 5))

    def test_ipv6_source(self):
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: Failed password for root from 2001:db8::1a2b port 55555 ssh2"))
        self.assertEqual(e.src_ip, "2001:db8::1a2b")

    def test_sshd_session_process_name_is_recognised(self):
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd-session[9]: Failed password for root from 203.0.113.5 port 22 ssh2"))
        self.assertEqual(e.source, "sshd")

    def test_raw_line_is_preserved(self):
        line = "Oct 13 11:16:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2"
        self.assertEqual(only_event(self, parse_one(line)).raw, line)


class IgnoredAndDeadLetterTests(unittest.TestCase):
    def test_known_noise_is_ignored_with_a_reason(self):
        cases = {
            "pam_unix(sshd:auth): check pass; user unknown": "pam-module",
            "Connection closed by invalid user x 203.0.113.5 port 22 [preauth]": "connection-closed",
            "Disconnected from user deploy 198.51.100.12 port 50122": "disconnected",
            "Server listening on 0.0.0.0 port 22.": "lifecycle",
            "PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root": "pam-summary",
        }
        for message, reason in cases.items():
            with self.subTest(message=message):
                r = parse_one(f"Oct 13 11:16:02 web01 sshd[1]: {message}")
                self.assertEqual((r.ignored, r.events, r.dead_letter), (reason, (), None))

    def test_other_programs_and_blank_lines_are_ignored(self):
        self.assertEqual(parse_one("Oct 13 11:16:02 web01 CRON[2]: whatever").ignored, "program:CRON")
        self.assertEqual(parse_one("").ignored, "blank")

    def test_unknown_sshd_message_is_a_dead_letter_not_dropped(self):
        line = "Oct 13 11:16:02 web01 sshd[1]: something sshd never said before"
        r = parse_one(line, offset=77)
        self.assertEqual((r.events, r.ignored), ((), None))
        self.assertEqual(
            (r.dead_letter.reason, r.dead_letter.raw, r.dead_letter.offset, r.dead_letter.source_id),
            ("unrecognised sshd message", line, 77, "test"),
        )

    def test_garbage_is_a_dead_letter(self):
        self.assertEqual(parse_one("\x00\x01 not a log line").dead_letter.reason, "unrecognised log envelope")

    def test_non_ip_in_the_address_slot_is_a_dead_letter(self):
        r = parse_one("Oct 13 11:16:02 web01 sshd[1]: Failed password for root from not-an-ip port 22 ssh2")
        self.assertIn("not an IP", r.dead_letter.reason)


class TimestampTests(unittest.TestCase):
    def test_iso_with_offset_converts_to_utc(self):
        e = only_event(self, parse_one(
            "2026-10-13T11:16:02.123456+02:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2"))
        self.assertEqual(e.timestamp, datetime(2026, 10, 13, 9, 16, 2, 123456, tzinfo=UTC))

    def test_iso_zulu_without_fraction(self):
        e = only_event(self, parse_one(
            "2026-10-13T11:16:02Z web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2"))
        self.assertEqual(e.timestamp, datetime(2026, 10, 13, 11, 16, 2, tzinfo=UTC))

    def test_syslog_time_is_converted_from_the_host_timezone(self):
        est = timezone(timedelta(hours=-5))
        e = only_event(self, parse_one(
            "Oct 13 11:16:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2", tz=est))
        self.assertEqual(e.timestamp, datetime(2026, 10, 13, 16, 16, 2, tzinfo=UTC))

    def test_space_padded_day(self):
        e = only_event(self, parse_one(
            "Mar  3 04:05:06 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2"))
        self.assertEqual(e.timestamp, datetime(2026, 3, 3, 4, 5, 6, tzinfo=UTC))

    def test_december_to_january_rollover_bumps_the_year(self):
        parser = SshdParser(year=2026)
        lines = [
            "Dec 31 23:59:58 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2",
            "Jan  1 00:00:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2",
            "Jan  1 00:00:03 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2",
        ]
        stamps = [only_event(self, parser.parse_line(l, "t", i)).timestamp for i, l in enumerate(lines)]
        self.assertEqual([s.year for s in stamps], [2026, 2027, 2027])
        self.assertTrue(stamps[0] < stamps[1] < stamps[2])

    def test_feb_29_in_a_non_leap_year_is_a_visible_dead_letter(self):
        line = "Feb 29 10:00:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2"
        self.assertIn("invalid timestamp", parse_one(line, year=2026).dead_letter.reason)
        self.assertIsNotNone(only_event(self, parse_one(line, year=2028)))


if __name__ == "__main__":
    unittest.main()
