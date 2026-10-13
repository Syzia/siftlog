"""Stage 8: the Cowrie honeypot parser.

The fixture, ``fixtures/cowrie_real_format.json``, has the field names, order
and compact layout of a real ``cowrie.json``. Its contents are invented: every
address is from a documentation range, and the session ids, hashes and sensor
id are made up. No real honeypot traffic is in this repository.
"""
import json
import os
import unittest
from collections import Counter
from datetime import datetime, timezone

from siftlog.events import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    COMMAND,
    CONNECTION,
    FILE_TRANSFER,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    make_event_id,
)
from siftlog.parsers import PARSERS, CowrieParser, ParserConfigError, SkipAddresses, SshdParser, build_parser
from siftlog.parsers.cowrie import MAX_FIELD
from siftlog.parsers.timestamps import parse_iso

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "cowrie_real_format.json")
SID = "file:test"


def record(eventid="cowrie.login.failed", **fields):
    base = {
        "session": "0a1b2c3d4e5f", "protocol": "ssh", "src_ip": "198.51.100.7", "src_port": 40000,
        "dst_ip": "192.0.2.10", "dst_port": 2222, "eventid": eventid, "sensor": "honeypot01",
        "uuid": "00000000-0000-4000-8000-000000000001", "timestamp": "2026-10-12T22:14:03.120394Z",
        "message": "",
    }  # fmt: skip
    base.update(fields)
    return {key: value for key, value in base.items() if value is not ...}


def parse(data, offset=0):
    line = data if isinstance(data, str) else json.dumps(data, separators=(",", ":"))
    return CowrieParser().parse_line(line + "\n", SID, offset)


def event_of(data):
    result = parse(data)
    assert result.dead_letter is None and result.ignored is None, result
    (event,) = result.events
    return event


class MappingTests(unittest.TestCase):
    def test_failed_login(self):
        event = event_of(record(username="root", password="123456", message="login attempt [root/123456] failed"))
        self.assertEqual((event.source, event.event_type, event.outcome), ("cowrie", AUTH_FAILURE, OUTCOME_FAILURE))
        self.assertEqual((event.src_ip, event.username, event.host), ("198.51.100.7", "root", "honeypot01"))
        self.assertEqual(event.timestamp, datetime(2026, 10, 12, 22, 14, 3, 120394, tzinfo=timezone.utc))
        self.assertEqual(event.extra, {
            "eventid": "cowrie.login.failed", "session": "0a1b2c3d4e5f", "protocol": "ssh",
            "password": "123456", "dst_port": 2222,
        })  # fmt: skip
        self.assertEqual(event.count, 1)

    def test_successful_login(self):
        event = event_of(record("cowrie.login.success", username="root", password="ubuntu"))
        self.assertEqual((event.event_type, event.outcome, event.username), (AUTH_SUCCESS, OUTCOME_SUCCESS, "root"))
        self.assertEqual(event.extra["password"], "ubuntu")

    def test_a_login_with_a_key_instead_of_a_password(self):
        event = event_of(record(username="root", fingerprint="aa:bb:cc", key="AAAAC3Nz", type="ssh-ed25519"))
        self.assertEqual((event.event_type, event.username), (AUTH_FAILURE, "root"))
        self.assertEqual(event.extra["fingerprint"], "aa:bb:cc")
        self.assertNotIn("password", event.extra)
        self.assertNotIn("key", event.extra)  # the fingerprint identifies the key; the key itself stays in `raw`

    def test_connection(self):
        event = event_of(record("cowrie.session.connect", message="New connection"))
        self.assertEqual((event.event_type, event.outcome, event.username), (CONNECTION, None, None))

    def test_command(self):
        event = event_of(record("cowrie.command.input", input="uname -a", message="CMD: uname -a"))
        self.assertEqual((event.event_type, event.outcome, event.username), (COMMAND, None, None))
        self.assertEqual(event.extra["input"], "uname -a")

    def test_file_upload_and_download(self):
        up = event_of(record("cowrie.session.file_upload", filename="sshd", outfile="var/x", shasum="ab" * 32))
        self.assertEqual((up.event_type, up.outcome), (FILE_TRANSFER, OUTCOME_SUCCESS))
        self.assertEqual((up.extra["direction"], up.extra["filename"], up.extra["shasum"]), ("upload", "sshd", "ab" * 32))

        down = event_of(record("cowrie.session.file_download", url="http://203.0.113.200/x", shasum="cd" * 32))
        self.assertEqual((down.event_type, down.outcome), (FILE_TRANSFER, OUTCOME_SUCCESS))
        self.assertEqual((down.extra["direction"], down.extra["url"]), ("download", "http://203.0.113.200/x"))

        failed = event_of(record("cowrie.session.file_download.failed", url="http://203.0.113.200/y"))
        self.assertEqual((failed.event_type, failed.outcome), (FILE_TRANSFER, OUTCOME_FAILURE))
        self.assertEqual((failed.extra["direction"], failed.extra["url"]), ("download", "http://203.0.113.200/y"))
        self.assertNotIn("shasum", failed.extra)

    def test_bookkeeping_events_are_ignored_with_their_event_id_as_the_reason(self):
        for eventid in ("cowrie.client.version", "cowrie.client.kex", "cowrie.session.closed", "cowrie.log.closed",
                        "cowrie.session.params", "cowrie.client.var", "cowrie.direct-tcpip.request"):
            result = parse(record(eventid))
            self.assertEqual((result.events, result.ignored, result.dead_letter), ((), f"eventid:{eventid}", None))

    def test_command_failed_is_ignored_because_it_repeats_command_input(self):
        # Cowrie logs command.input for every line typed, then command.failed if it was not found.
        # Counting both would double the command.
        self.assertEqual(parse(record("cowrie.command.failed", input="foo")).ignored, "eventid:cowrie.command.failed")

    def test_an_event_id_cowrie_adds_in_future_is_ignored_not_dead(self):
        result = parse(record("cowrie.something.new"))
        self.assertEqual((result.ignored, result.dead_letter), ("eventid:cowrie.something.new", None))

    def test_blank_line(self):
        self.assertEqual(CowrieParser().parse_line("  \n", SID, 0).ignored, "blank")


class IdentityTests(unittest.TestCase):
    def test_id_comes_from_where_the_line_was_not_what_it_says(self):
        same = record(username="root", password="x")
        first, second = parse(same, offset=0).events[0], parse(same, offset=250).events[0]
        self.assertEqual(first.id, make_event_id(SID, 0))
        self.assertNotEqual(first.id, second.id)  # two identical lines are two events
        self.assertEqual((second.source_id, second.offset), (SID, 250))

    def test_raw_is_the_untouched_line(self):
        line = json.dumps(record(username="root", password="x"))  # with spaces, unlike Cowrie
        self.assertEqual(CowrieParser().parse_line(line + "\r\n", SID, 0).events[0].raw, line)

    def test_parser_has_no_state_and_needs_no_year(self):
        parser = CowrieParser()
        self.assertFalse(parser.needs_year)
        self.assertEqual(parser.state(), {})
        parser.restore({})
        parser.restore({"year": 1999, "last_month": 12})  # a checkpoint written by another parser changes nothing
        self.assertEqual(parser.parse_line(json.dumps(record()), SID, 0).events[0].timestamp.year, 2026)
        self.assertTrue(SshdParser.needs_year)
        self.assertEqual(sorted(PARSERS), ["cowrie", "sshd"])


class TimestampTests(unittest.TestCase):
    def test_offsets_are_converted_to_utc(self):
        for text, expected in (
            ("2026-10-12T22:14:03.120394Z", datetime(2026, 10, 12, 22, 14, 3, 120394, tzinfo=timezone.utc)),
            ("2026-10-12T22:14:03Z", datetime(2026, 10, 12, 22, 14, 3, tzinfo=timezone.utc)),
            ("2026-10-13T08:14:03.5+10:00", datetime(2026, 10, 12, 22, 14, 3, 500000, tzinfo=timezone.utc)),
            ("2026-10-12T17:44:03-0430", datetime(2026, 10, 12, 22, 14, 3, tzinfo=timezone.utc)),
            ("2026-10-12T22:14:03.1203949999Z", datetime(2026, 10, 12, 22, 14, 3, 120394, tzinfo=timezone.utc)),
        ):
            self.assertEqual(event_of(record(timestamp=text)).timestamp, expected, text)
            self.assertEqual(parse_iso(text), expected)

    def test_unusable_timestamps_are_dead_letters(self):
        for bad in ("2026-10-12T22:14:03", "2026-10-12 22:14:03Z", "2026-13-40T22:14:03Z", "yesterday", "",
                    1760307243, 1760307243.5, None, ["2026-10-12T22:14:03Z"], "2026-10-12T22:14:03Z trailing",
                    "2026-10-12T22:14:03Z\n"):
            result = parse(record(timestamp=bad))
            self.assertEqual(result.events, (), bad)
            self.assertEqual(result.dead_letter.reason, "missing or invalid timestamp", bad)
        self.assertEqual(parse(record(timestamp=...)).dead_letter.reason, "missing or invalid timestamp")


class HostileInputTests(unittest.TestCase):
    """Usernames, passwords, commands, file names and URLs are whatever the attacker typed."""

    def test_things_that_are_not_cowrie_records_are_dead_letters(self):
        for line, reason in (
            ("Oct 12 22:14:03 web01 sshd[1]: Failed password for root from 198.51.100.7 port 22 ssh2", "not valid JSON"),
            ('{"eventid": "cowrie.login.failed", "timestamp": ', "not valid JSON"),  # cut off mid-write
            ("[" * 50_000, "not valid JSON"),  # nesting deep enough to exhaust the parser
            ('["cowrie.login.failed"]', "not a JSON object"),
            ('"cowrie.login.failed"', "not a JSON object"),
            ("12", "not a JSON object"),
            ("null", "not a JSON object"),
            ("{}", "missing or malformed eventid"),
        ):
            result = parse(line)
            self.assertEqual(result.events, (), line[:40])
            self.assertEqual(result.dead_letter.reason, reason, line[:40])
            self.assertEqual((result.dead_letter.source_id, result.dead_letter.offset), (SID, 0))
            self.assertEqual(result.dead_letter.raw, line)

    def test_a_malformed_event_id_is_a_dead_letter_and_never_becomes_a_reason(self):
        for bad in (None, 7, ["cowrie.login.failed"], "", "x" * 200, "cowrie login", "Cowrie.Login", "a\nb",
                    "cowrie.login.failed\n"):
            result = parse(record(eventid=bad))
            self.assertEqual(result.dead_letter.reason, "missing or malformed eventid", bad)
            self.assertIsNone(result.ignored)

    def test_source_address_must_be_a_real_address_in_a_string(self):
        for bad in (None, "", "not-an-ip", "198.51.100.999", "198.51.100.7 ", 5, True, ["198.51.100.7"], {"ip": 1}):
            result = parse(record(src_ip=bad))
            self.assertEqual(result.events, (), bad)
            self.assertEqual(result.dead_letter.reason, "missing or invalid src_ip", bad)
        self.assertEqual(parse(record(src_ip=...)).dead_letter.reason, "missing or invalid src_ip")
        self.assertEqual(event_of(record(src_ip="2001:db8::7")).src_ip, "2001:db8::7")

    def test_an_ignored_event_needs_no_address(self):
        # Cowrie writes some housekeeping lines with no session. They are still recognised.
        self.assertEqual(parse(record("cowrie.session.closed", src_ip=...)).ignored, "eventid:cowrie.session.closed")

    def test_a_username_cannot_inject_fields(self):
        # In sshd's free text a username can impersonate the rest of the line. In JSON it is
        # just a string, however much it looks like more fields.
        sneaky = 'root","src_ip":"203.0.113.250","eventid":"cowrie.session.closed'
        event = event_of(record(username=sneaky, password='x"}\n{"eventid":"cowrie.login.success'))
        self.assertEqual((event.src_ip, event.event_type, event.username), ("198.51.100.7", AUTH_FAILURE, sneaky))

    def test_a_command_with_newlines_is_still_one_event(self):
        event = event_of(record("cowrie.command.input", input="echo a\necho b\r\n\x00\x1b[2J"))
        self.assertEqual(event.extra["input"], "echo a\necho b\r\n\x00\x1b[2J")
        self.assertNotIn("\n", event.raw)

    def test_fields_of_the_wrong_type_are_treated_as_absent(self):
        event = event_of(record(username=["root"], password={"a": 1}, session=12, sensor=None, dst_port="2222"))
        self.assertEqual((event.username, event.host), (None, None))
        self.assertEqual(event.extra, {"eventid": "cowrie.login.failed", "protocol": "ssh"})
        self.assertNotIn("dst_port", event_of(record(dst_port=True)).extra)

    def test_long_values_are_bounded_in_fields_but_not_in_raw(self):
        blob = "A" * (MAX_FIELD * 3)
        event = event_of(record("cowrie.command.input", input=blob, username=blob))
        self.assertEqual((len(event.extra["input"]), len(event.username)), (MAX_FIELD, MAX_FIELD))
        self.assertIn(blob, event.raw)

    def test_unknown_fields_are_not_copied(self):
        event = event_of(record(username="root", password="x", surprise="value", message="login attempt"))
        self.assertEqual(sorted(event.extra), ["dst_port", "eventid", "password", "protocol", "session"])


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = []
        parser, offset = CowrieParser(), 0
        with open(FIXTURE, "rb") as fh:
            for raw in fh:
                cls.results.append(parser.parse_line(raw.decode("utf-8"), SID, offset))
                offset += len(raw)
        cls.events = [event for result in cls.results for event in result.events]

    def test_every_line_is_understood(self):
        self.assertEqual(len(self.results), 66)
        self.assertEqual([r.dead_letter for r in self.results if r.dead_letter], [])
        self.assertEqual(len(self.events), 31)

    def test_event_types(self):
        self.assertEqual(Counter(e.event_type for e in self.events), {
            CONNECTION: 10, AUTH_SUCCESS: 9, COMMAND: 7, FILE_TRANSFER: 3, AUTH_FAILURE: 2,
        })  # fmt: skip
        self.assertEqual({e.source for e in self.events}, {"cowrie"})
        self.assertEqual({e.host for e in self.events}, {"honeypot01"})

    def test_ignored_reasons(self):
        self.assertEqual(Counter(r.ignored for r in self.results if r.ignored), {
            "eventid:cowrie.client.version": 10, "eventid:cowrie.client.kex": 10, "eventid:cowrie.session.closed": 10,
            "eventid:cowrie.client.var": 1, "eventid:cowrie.session.params": 1, "eventid:cowrie.command.failed": 1,
            "eventid:cowrie.log.closed": 1, "eventid:cowrie.direct-tcpip.request": 1,
        })  # fmt: skip

    def test_one_visit_reads_as_a_story(self):
        visit = [e for e in self.events if e.extra["session"] == "2c3d4e5f6071"]
        self.assertEqual([e.event_type for e in visit], [
            CONNECTION, AUTH_FAILURE, AUTH_FAILURE, AUTH_SUCCESS, COMMAND, COMMAND, COMMAND, COMMAND,
            FILE_TRANSFER, COMMAND, FILE_TRANSFER, COMMAND, COMMAND,
        ])  # fmt: skip
        self.assertEqual([e.extra["password"] for e in visit[1:4]], ["root", "123456", "admin"])
        self.assertEqual(visit[4].extra["input"], "uname -a")
        self.assertEqual([e.outcome for e in visit if e.event_type == FILE_TRANSFER], [OUTCOME_SUCCESS, OUTCOME_FAILURE])
        self.assertEqual(visit, sorted(visit, key=lambda e: e.timestamp))

    def test_fixture_holds_only_documentation_addresses(self):
        # The project rule: no real attack traffic in the repository. Guard the fixture against
        # a real log line being pasted in later.
        import ipaddress

        documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
        with open(FIXTURE, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        for item in records:
            for name in ("src_ip", "dst_ip"):
                self.assertTrue(any(ipaddress.ip_address(item[name]) in n for n in documentation), item[name])
        self.assertEqual({item["sensor"] for item in records}, {"honeypot01"})
        self.assertEqual({item["uuid"] for item in records}, {"00000000-0000-4000-8000-000000000001"})


class BuildParserTests(unittest.TestCase):
    def test_sshd_needs_a_year_and_cowrie_does_not(self):
        self.assertIsInstance(build_parser("cowrie"), CowrieParser)
        self.assertIsInstance(build_parser("sshd", year=2026), SshdParser)
        with self.assertRaisesRegex(ParserConfigError, "--year is required for --source sshd"):
            build_parser("sshd")
        with self.assertRaisesRegex(ParserConfigError, "unknown source 'nginx'"):
            build_parser("nginx")

    def test_own_addresses_are_left_out_and_counted_as_ignored(self):
        parser = build_parser("cowrie", ignore_ips=["198.51.100.7", "2001:db8::/32"])
        self.assertIsInstance(parser, SkipAddresses)
        self.assertEqual((parser.source, parser.needs_year), ("cowrie", False))
        for mine in ("198.51.100.7", "2001:db8::7", "2001:0db8:0000:0000:0000:0000:0000:0007"):
            result = parser.parse_line(json.dumps(record(src_ip=mine, username="root")), SID, 0)
            self.assertEqual((result.events, result.ignored, result.dead_letter), ((), "own-address", None), mine)
        other = parser.parse_line(json.dumps(record(src_ip="198.51.100.8", username="root")), SID, 0)
        self.assertEqual(other.events[0].src_ip, "198.51.100.8")

    def test_skipping_addresses_changes_nothing_else(self):
        parser = build_parser("cowrie", ignore_ips=["198.51.100.7"])
        self.assertEqual(parser.parse_line("not json", SID, 0).dead_letter.reason, "not valid JSON")
        self.assertEqual(parser.parse_line(json.dumps(record("cowrie.client.kex")), SID, 0).ignored,
                         "eventid:cowrie.client.kex")
        wrapped = build_parser("sshd", year=2025, ignore_ips=["198.51.100.7"])
        self.assertEqual(wrapped.state(), {"year": 2025, "last_month": None})
        wrapped.restore({"year": 2031, "last_month": 3})
        self.assertEqual(wrapped.state(), {"year": 2031, "last_month": 3})
        line = "Mar  1 10:00:00 web01 sshd[1]: Failed password for root from 198.51.100.7 port 22 ssh2"
        self.assertEqual(wrapped.parse_line(line, SID, 0).ignored, "own-address")
        self.assertEqual(wrapped.parse_line(line.replace("100.7", "100.9"), SID, 0).events[0].timestamp.year, 2031)

    def test_a_bad_address_is_refused(self):
        for bad in ("my-laptop", "198.51.100.999", "198.51.100.0/40", ""):
            with self.assertRaisesRegex(ParserConfigError, "not an IP address or network"):
                build_parser("cowrie", ignore_ips=[bad])


if __name__ == "__main__":
    unittest.main()
