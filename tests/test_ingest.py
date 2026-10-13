"""Stage 2 acceptance: ingest at volume, re-ingest is a no-op, query by IP and time."""
import gzip
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from siftlog.events import AUTH_FAILURE, AUTH_SUCCESS
from siftlog.ingest import MAX_LINE_BYTES, file_identity, ingest_file
from siftlog.parsers import SshdParser
from siftlog.simulator import simulate, write_files
from siftlog.store import EventStore

HERE = os.path.dirname(__file__)
FIXTURE = os.path.join(HERE, "fixtures", "sshd_real_format.log")
T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)


def ingest(path, store, year=2026, **kwargs):
    return ingest_file(path, SshdParser(year=year), store, **kwargs)


def fail_line(second, ip="203.0.113.5", user="root"):
    return (
        f"Mar  1 10:{second // 60:02d}:{second % 60:02d} web01 sshd[1]: "
        f"Failed password for {user} from {ip} port 22 ssh2"
    )


def write_bytes(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


class FixtureIngestTests(unittest.TestCase):
    def test_reingesting_the_same_file_changes_nothing(self):
        with open(FIXTURE) as fh:
            total_lines = sum(1 for _ in fh)
        with EventStore() as store:
            first = ingest(FIXTURE, store)
            self.assertEqual(first.lines, total_lines)
            self.assertEqual((first.events_parsed, first.events_new, first.events_duplicate), (14, 14, 0))
            self.assertEqual(first.ignored_total, total_lines - 14)
            self.assertEqual((first.dead_letters, store.count()), (0, 14))

            second = ingest(FIXTURE, store)
            self.assertEqual((second.events_parsed, second.events_new, second.events_duplicate), (14, 0, 14))
            self.assertEqual(store.count(), 14)
            self.assertEqual(store.count(weighted=True), 18)  # the "repeated 5 times" row carries 5

    def test_dead_letters_are_stored_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "auth.log")
            write_bytes(path, (fail_line(1) + "\nthis is not a log line\n" + fail_line(2) + "\n").encode())
            with EventStore() as store:
                self.assertEqual(ingest(path, store).dead_letters_new, 1)
                self.assertEqual(ingest(path, store).dead_letters_new, 0)
                (letter,) = store.dead_letters()
                self.assertEqual((letter.raw, letter.reason), ("this is not a log line", "unrecognised log envelope"))
                self.assertEqual(letter.offset, len(fail_line(1)) + 1)


class SimulatedIngestTests(unittest.TestCase):
    def test_ground_truth_is_recoverable_by_ip_and_time(self):
        sim = simulate()
        with tempfile.TemporaryDirectory() as tmp:
            log, labels = os.path.join(tmp, "sim.log"), os.path.join(tmp, "sim.labels.json")
            write_files(sim, log, labels)
            with EventStore() as store:
                report = ingest(log, store)
                self.assertEqual(report.dead_letters, 0)
                self.assertEqual(ingest(log, store).events_new, 0)

                by_kind = {label.kind: label for label in sim.labels}
                one_second = timedelta(seconds=1)

                brute = by_kind["brute_force"]
                got = store.query(src_ip=brute.group_key, event_type=AUTH_FAILURE,
                                  since=brute.start, until=brute.end + one_second)
                self.assertEqual(len(got), 40)
                # Nothing from that attacker falls outside its own scenario window.
                self.assertEqual(store.count(src_ip=brute.group_key, event_type=AUTH_FAILURE), 40)

                spray = by_kind["password_spray"]
                self.assertEqual(store.count(src_ip=spray.group_key, event_type=AUTH_FAILURE), 30)

                travel = store.query(username="carol", event_type=AUTH_SUCCESS)
                self.assertEqual([e.src_ip for e in travel], ["198.51.100.10", "203.0.113.50"])
                self.assertLess(travel[0].timestamp, travel[1].timestamp)

                # A narrow window before the attack starts sees none of it.
                self.assertEqual(
                    store.count(src_ip=brute.group_key, until=brute.start), 0
                )


class VolumeTests(unittest.TestCase):
    """The stage 2 milestone: 100k events in, re-ingest is a no-op, queries by IP/time are right."""

    N = 100_000

    def test_100k_events(self):
        users = ["root", "admin", "ubuntu", "oracle", "test", "git", "pi"]
        stamp = lambda i: (T0 + timedelta(seconds=i // 2)).strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
        ip = lambda i: f"203.0.113.{i % 250 + 1}"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "big.log")
            with open(path, "w") as fh:
                for i in range(self.N):
                    fh.write(
                        f"{stamp(i)} web01 sshd[1]: Failed password for {users[i % 7]} "
                        f"from {ip(i)} port 22 ssh2\n"
                    )
            with EventStore() as store:
                first = ingest(path, store)
                self.assertEqual((first.lines, first.events_new, first.dead_letters), (self.N, self.N, 0))
                self.assertEqual(store.count(), self.N)

                again = ingest(path, store)
                self.assertEqual((again.events_parsed, again.events_new), (self.N, 0))
                self.assertEqual(store.count(), self.N)

                since, until = T0 + timedelta(seconds=1000), T0 + timedelta(seconds=2000)
                self.assertEqual(store.count(since=since, until=until), 2000)  # i in [2000, 4000)
                self.assertEqual(store.count(src_ip="203.0.113.7"), self.N // 250)
                want = len([i for i in range(2000, 4000) if i % 250 == 6])
                got = store.query(src_ip="203.0.113.7", since=since, until=until)
                self.assertEqual((len(got), want), (want, want))
                self.assertTrue(all(since <= e.timestamp < until and e.src_ip == "203.0.113.7" for e in got))
                self.assertEqual([e.timestamp for e in got], sorted(e.timestamp for e in got))
                self.assertNotIn("SCAN events", " ".join(store.explain_query(src_ip="203.0.113.7", since=since)))


class RotationAndGrowthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def p(self, name):
        return os.path.join(self.tmp.name, name)

    def test_renamed_and_gzipped_copies_are_not_double_counted(self):
        shutil.copy(FIXTURE, self.p("auth.log"))
        shutil.copy(FIXTURE, self.p("auth.log.1"))  # logrotate renamed it
        with open(FIXTURE, "rb") as src, gzip.open(self.p("auth.log.2.gz"), "wb") as dst:
            dst.write(src.read())  # ...and later compressed it
        with EventStore() as store:
            self.assertEqual(ingest(self.p("auth.log"), store).events_new, 14)
            for name in ("auth.log.1", "auth.log.2.gz"):
                with self.subTest(name=name):
                    self.assertEqual(ingest(self.p(name), store).events_new, 0)
            self.assertEqual(store.count(), 14)

    def test_distinct_files_do_not_collide_at_the_same_offsets(self):
        write_bytes(self.p("a.log"), (fail_line(1, ip="203.0.113.1") + "\n").encode())
        write_bytes(self.p("b.log"), (fail_line(2, ip="203.0.113.2") + "\n").encode())
        self.assertNotEqual(file_identity(self.p("a.log")), file_identity(self.p("b.log")))
        with EventStore() as store:
            ingest(self.p("a.log"), store)
            ingest(self.p("b.log"), store)
            self.assertEqual(store.count(), 2)

    def test_an_appended_file_only_adds_the_new_lines(self):
        lines = simulate().lines
        path = self.p("auth.log")
        write_bytes(path, ("\n".join(lines[:400]) + "\n").encode())
        with EventStore() as growing, EventStore() as whole:
            first = ingest(path, growing)
            with open(path, "ab") as fh:
                fh.write(("\n".join(lines[400:]) + "\n").encode())
            second = ingest(path, growing)
            full = ingest(path, whole)

            self.assertEqual(second.events_duplicate, first.events_new)
            self.assertEqual(first.events_new + second.events_new, full.events_new)
            self.assertEqual(
                [e.id for e in growing.query()], [e.id for e in whole.query()]
            )

    def test_a_half_written_last_line_waits_for_the_next_run(self):
        path = self.p("auth.log")
        done = fail_line(1) + "\n" + fail_line(2) + "\n"
        partial = fail_line(3)[:-20]  # cut mid-line, no newline: sshd is still writing
        write_bytes(path, (done + partial).encode())
        with EventStore() as store:
            first = ingest(path, store)
            self.assertTrue(first.skipped_unterminated_tail)
            self.assertEqual((first.events_new, first.dead_letters, store.dead_letter_count()), (2, 0, 0))

            write_bytes(path, (done + fail_line(3) + "\n").encode())  # the write completes
            second = ingest(path, store)
            self.assertFalse(second.skipped_unterminated_tail)
            self.assertEqual((second.events_new, store.count()), (1, 3))

    def test_unterminated_tail_can_be_included_explicitly(self):
        path = self.p("auth.log")
        write_bytes(path, (fail_line(1) + "\n" + fail_line(2)).encode())
        with EventStore() as store:
            report = ingest(path, store, include_unterminated=True)
            self.assertEqual((report.events_new, report.skipped_unterminated_tail), (2, False))

    def test_explicit_source_id_overrides_file_identity(self):
        write_bytes(self.p("a.log"), (fail_line(1) + "\n").encode())
        with EventStore() as store:
            ingest(self.p("a.log"), store, source_id="host-a:auth")
            ingest(self.p("a.log"), store, source_id="host-b:auth")
            self.assertEqual(store.count(), 2)  # same bytes, two declared streams
            self.assertEqual({e.source_id for e in store.query()}, {"host-a:auth", "host-b:auth"})


class HostileFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "auth.log")

    def test_an_overlong_line_is_bounded_and_does_not_shift_later_offsets(self):
        before, after = fail_line(1), fail_line(2)
        huge = b"A" * 200_000
        write_bytes(self.path, before.encode() + b"\n" + huge + b"\n" + after.encode() + b"\n")
        with EventStore() as store:
            report = ingest(self.path, store)
            self.assertEqual((report.lines, report.events_new, report.dead_letters), (3, 2, 1))
            (letter,) = store.dead_letters()
            self.assertLessEqual(len(letter.raw), MAX_LINE_BYTES)
            self.assertEqual(letter.offset, len(before) + 1)
            second = store.query()[-1]
            self.assertEqual(second.offset, len(before) + 1 + len(huge) + 1)

    def test_invalid_utf8_does_not_crash_ingest(self):
        line = b"Mar  1 10:00:01 web01 sshd[1]: Failed password for invalid user \xff\xfe from 203.0.113.5 port 22 ssh2\n"
        write_bytes(self.path, line)
        with EventStore() as store:
            self.assertEqual(ingest(self.path, store).events_new, 1)
            self.assertEqual(store.query()[0].username, "��")

    def test_crlf_line_endings(self):
        write_bytes(self.path, (fail_line(1) + "\r\n" + fail_line(2) + "\r\n").encode())
        with EventStore() as store:
            report = ingest(self.path, store)
            self.assertEqual((report.events_new, report.dead_letters), (2, 0))
            self.assertEqual(store.query()[1].offset, len(fail_line(1)) + 2)

    def test_empty_file(self):
        write_bytes(self.path, b"")
        with EventStore() as store:
            report = ingest(self.path, store)
            self.assertEqual((report.lines, report.events_new, store.count()), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
