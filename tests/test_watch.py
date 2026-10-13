"""Stage 6 acceptance: append to a log file, and an alert appears in seconds."""
import contextlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

from siftlog.enrich import TableGeoResolver
from siftlog.engine import ReplayEngine, load_rules
from siftlog.evaluate import simulated_dataset
from siftlog.parsers import SshdParser
from siftlog.simulator import FAKE_GEO, simulate
from siftlog.store import EventStore
from siftlog.store.alerts import SYSTEM_ACTOR
from siftlog.watch import Watcher
from siftlog.watch import main as watch_cli

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
BASE = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
LATENESS = 2.0


def line(seconds, ip="203.0.113.5", user="root", ok=False):
    stamp = (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")
    verb = "Accepted" if ok else "Failed"
    return f"{stamp} web01 sshd[1]: {verb} password for {user} from {ip} port 22 ssh2\n"


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class WatchTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.log = os.path.join(tmp.name, "auth.log")
        self.db = os.path.join(tmp.name, "events.db")
        open(self.log, "w").close()
        self.clock = Clock()
        self.rules = load_rules(RULES_DIR)
        self.store = EventStore(self.db)
        self.addCleanup(self.store.close)

    def append(self, *lines, path=None):
        with open(path or self.log, "a") as fh:
            fh.writelines(lines)

    def watcher(self, year=2026, **kwargs):
        kwargs.setdefault("lateness", LATENESS)
        return Watcher([self.log], self.store, self.rules, lambda: SshdParser(year=year), clock=self.clock, **kwargs)

    def settle(self, watcher):
        """Let the ordering wait pass, then take a step. Returns that step's report."""
        watcher.step()
        self.clock.now += LATENESS
        return watcher.step()

    def brute(self):
        (stored,) = self.store.list_alerts(rule_id="ssh-brute-force")
        return stored


class AcceptanceTests(WatchTestCase):
    def test_appending_to_the_log_raises_an_alert_within_seconds(self):
        watcher = self.watcher()
        watcher.start()
        self.append(*[line(i) for i in range(10)])

        first = watcher.step()
        self.assertEqual((first.lines, first.events, first.opened), (10, 10, []))  # read and stored at once...
        self.assertEqual(self.store.count(), 10)
        self.assertEqual(self.store.count_alerts(), 0)  # ...but held briefly so stragglers can be ordered

        self.clock.now += LATENESS  # two seconds later
        (opened,) = watcher.step().opened
        self.assertEqual((opened.rule_id, opened.group_key, opened.event_count), ("ssh-brute-force", "203.0.113.5", 10))
        stored = self.brute()
        self.assertEqual((stored.alert.id, stored.status), (opened.id, "open"))
        self.assertEqual(len(self.store.alert_events(opened.id)), 10)  # with its evidence, ready for the API

        self.append(*[line(10 + i) for i in range(5)])
        (grown,) = self.settle(watcher).updated
        self.assertEqual((grown.id, grown.event_count), (opened.id, 15))
        self.assertEqual((self.store.count_alerts(), self.brute().alert.event_count), (1, 15))

    def test_no_wait_at_all_when_lateness_is_zero(self):
        watcher = self.watcher(lateness=0)
        watcher.start()
        self.append(*[line(i) for i in range(10)])
        self.assertEqual(len(watcher.step().opened), 1)

    def test_step_before_start_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.watcher().step()

    def test_startup_agrees_with_the_batch_pipeline(self):
        with open(self.log, "w") as fh:
            fh.write("\n".join(simulate(seed=3).lines) + "\n")
        report = self.watcher(resolver=TableGeoResolver(FAKE_GEO)).start()
        expected = ReplayEngine(self.rules).run(simulated_dataset(3).events)
        self.assertEqual(report.new, 7)
        self.assertEqual(
            sorted((s.alert.id, s.alert.rule_id, s.alert.event_count) for s in self.store.list_alerts()),
            sorted((a.id, a.rule_id, a.event_count) for a in expected),
        )


class RestartTests(WatchTestCase):
    def test_restart_mid_attack_continues_the_same_alert(self):
        first = self.watcher()
        first.start()
        self.append(*[line(i) for i in range(12)])
        (opened,) = self.settle(first).opened
        self.store.set_alert_status(opened.id, "ack", note="on it")
        first.close()

        second = self.watcher()  # the process restarts while the attack is still going
        report = second.start()
        self.assertEqual((report.new, report.unchanged, report.removed), (0, 1, 0))
        self.append(*[line(12 + i) for i in range(5)])
        (grown,) = self.settle(second).updated
        self.assertEqual((grown.id, grown.event_count), (opened.id, 17))
        stored = self.brute()
        self.assertEqual((self.store.count_alerts(), stored.status, stored.note), (1, "ack", "on it"))

    def test_a_closed_alert_reopens_when_the_attack_continues_live(self):
        watcher = self.watcher()
        watcher.start()
        self.append(*[line(i) for i in range(10)])
        (opened,) = self.settle(watcher).opened
        self.store.set_alert_status(opened.id, "closed", note="blocked")
        self.append(*[line(10 + i) for i in range(3)])
        self.settle(watcher)
        self.assertEqual(self.brute().status, "open")
        self.assertEqual(self.store.alert_history(opened.id)[-1].actor, SYSTEM_ACTOR)

    def test_resumes_from_its_checkpoint_without_rereading(self):
        self.append(*[line(i) for i in range(3)])
        first = self.watcher()
        first.start()
        first.close()
        (source_id,) = {e.source_id for e in self.store.query()}
        self.assertEqual(self.store.get_checkpoint(source_id)[0], os.path.getsize(self.log))

        second = self.watcher()
        second.start()
        self.assertEqual((second.step().lines, self.store.count()), (0, 3))
        self.append(line(3))
        self.assertEqual((second.step().lines, self.store.count()), (1, 4))

    def test_the_year_reached_survives_a_restart(self):
        # Syslog lines carry no year. A restart must not forget that the log has passed New Year.
        with open(self.log, "w") as fh:
            fh.write("Dec 31 23:59:58 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n")
        first = self.watcher(year=2026)
        first.start()
        first.close()
        self.append("Jan  1 00:00:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n")
        self.append("Jan  1 00:00:03 web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n")
        self.watcher(year=2026).start()  # restarted with the same flag as before
        self.assertEqual([e.timestamp.year for e in self.store.query()], [2026, 2027, 2027])


class LiveLogTests(WatchTestCase):
    def test_an_attack_spanning_a_log_rotation_is_one_alert(self):
        watcher = self.watcher()
        watcher.start()
        self.append(*[line(i) for i in range(6)])
        self.settle(watcher)
        self.append(line(6))  # written just before logrotate runs
        os.rename(self.log, self.log + ".1")
        self.append(*[line(7 + i) for i in range(5)])  # the new auth.log
        (opened,) = self.settle(watcher).opened
        self.assertEqual(opened.event_count, 12)
        self.assertEqual((self.store.count(), self.store.count_alerts()), (12, 1))
        self.assertEqual(len({e.source_id for e in self.store.query()}), 2)  # two files, one attack

    def test_a_rotated_in_file_continues_the_year_the_old_one_reached(self):
        # The new auth.log starts on 1 January. Nothing in it says which year, and the
        # operator's --year flag is by now a year out of date.
        syslog = "{} web01 sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
        with open(self.log, "w") as fh:
            fh.write(syslog.format("Dec 31 23:59:58"))
        watcher = self.watcher(year=2026, lateness=0)
        watcher.start()
        os.rename(self.log, self.log + ".1")
        self.append(syslog.format("Jan  1 00:00:02"))
        watcher.step()
        self.assertEqual([e.timestamp.year for e in self.store.query()], [2026, 2027])

    def test_lines_that_do_not_parse_become_dead_letters(self):
        watcher = self.watcher()
        watcher.start()
        self.append(line(0), "this is not a log line\n", line(1))
        report = watcher.step()
        self.assertEqual((report.lines, report.events, report.dead_letters), (3, 2, 1))
        self.assertEqual(self.store.dead_letter_count(), 1)

    def test_a_half_written_line_waits_for_the_rest(self):
        watcher = self.watcher(lateness=0)
        watcher.start()
        whole = line(0)
        self.append(whole[:40])
        self.assertEqual(watcher.step().lines, 0)
        self.append(whole[40:])
        self.assertEqual((watcher.step().events, self.store.dead_letter_count()), (1, 0))

    def test_events_too_late_to_order_are_stored_but_not_evaluated(self):
        watcher = self.watcher(lateness=0)
        watcher.start()
        self.append(line(100))
        watcher.step()
        self.append(line(50))  # happened earlier, arrived after the later one was processed
        report = watcher.step()
        self.assertEqual((report.late_events, self.store.count()), (1, 2))

    def test_the_ordering_wait_absorbs_that_same_disorder(self):
        watcher = self.watcher()  # two seconds of lateness
        watcher.start()
        self.append(line(100))
        watcher.step()
        self.clock.now += 1.0
        self.append(line(50))
        watcher.step()
        self.clock.now += LATENESS
        self.assertEqual(watcher.step().late_events, 0)
        self.assertEqual(watcher.engine.late_events, 0)

    def test_closing_processes_what_was_still_waiting(self):
        watcher = self.watcher(lateness=60)
        watcher.start()
        self.append(*[line(i) for i in range(10)])
        watcher.step()
        self.assertEqual(self.store.count_alerts(), 0)
        self.assertEqual(len(watcher.close().opened), 1)
        self.assertEqual(self.store.count_alerts(), 1)


class CliTests(WatchTestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = watch_cli([self.log, "--db", self.db, "--rules", RULES_DIR, *argv])
        return code, out.getvalue()

    def test_once_catches_up_detects_and_saves(self):
        with open(self.log, "w") as fh:
            fh.write("\n".join(simulate(seed=1234).lines) + "\n")
        self.store.close()
        code, out = self.run_cli("--year", "2026", "--simulated-geo", "--once")
        self.assertEqual(code, 0)
        self.assertIn("caught up: 662 events stored, 7 alert(s) (7 new", out)
        with EventStore(self.db) as store:
            self.assertEqual(store.count_alerts(), 7)
        self.assertIn("(0 new", self.run_cli("--year", "2026", "--simulated-geo", "--once")[1])  # and again: nothing new

    def test_bad_arguments(self):
        for argv in (["--once"], ["--year", "2026", "--poll", "0"], ["--year", "2026", "--lateness", "-1"],
                     ["--year", "2026", "--tz", "Mars/Olympus"], ["--year", "2026", "--geoip", "/nonexistent.mmdb"]):  # fmt: skip
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as stop:
                self.run_cli(*argv)
            self.assertEqual(stop.exception.code, 2)


class RealProcessTests(WatchTestCase):
    def test_a_stop_signal_shuts_down_cleanly_and_loses_nothing(self):
        # Run the real command, and stop it the way `kill` or systemd would. Lateness is
        # set far too long for the alert to appear on its own, so the only way it can be
        # stored is by the shutdown path evaluating what was still waiting.
        self.store.close()
        root = os.path.dirname(os.path.dirname(__file__))
        process = subprocess.Popen(
            [sys.executable, "-u", "-m", "siftlog.watch", self.log, "--db", self.db, "--rules", RULES_DIR,
             "--year", "2026", "--poll", "0.1", "--lateness", "600"],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )  # fmt: skip
        try:
            self.assertIn("caught up", process.stdout.readline())
            self.append(*[line(i) for i in range(10)])
            deadline = time.time() + 10
            while time.time() < deadline:
                with EventStore(self.db) as store:
                    if store.count() == 10:
                        break
                time.sleep(0.05)
            with EventStore(self.db) as store:
                self.assertEqual((store.count(), store.count_alerts()), (10, 0))  # read, but still waiting

            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertEqual(process.returncode, 0, output)
        self.assertIn("stopping", output)
        with EventStore(self.db) as store:
            (stored,) = store.list_alerts()
            self.assertEqual((stored.alert.rule_id, stored.alert.event_count), ("ssh-brute-force", 10))


if __name__ == "__main__":
    unittest.main()
