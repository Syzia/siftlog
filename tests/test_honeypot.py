"""Stage 8 acceptance: a Cowrie honeypot log goes through the whole pipeline.

Log file -> parser -> event store -> rules -> alerts -> API, with the same
commands a person would type. The fixture is invented data in Cowrie's layout
(see test_cowrie_parser).
"""
import contextlib
import gzip
import io
import json
import os
import shutil
import tempfile
import unittest

from fastapi.testclient import TestClient

from siftlog.api import create_app
from siftlog.engine import ReplayEngine, load_rules
from siftlog.engine.__main__ import main as engine_cli
from siftlog.evaluate import scored_rules, simulated_dataset
from siftlog.events import COMMAND, FILE_TRANSFER
from siftlog.ingest import ingest_file
from siftlog.ingest.__main__ import main as ingest_cli
from siftlog.parsers import CowrieParser, build_parser
from siftlog.store import EventStore
from siftlog.watch import Watcher
from siftlog.watch import main as watch_cli

ROOT = os.path.dirname(os.path.dirname(__file__))
RULES_DIR = os.path.join(ROOT, "rules")
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "cowrie_real_format.json")
TOKEN = "test-token-not-a-real-secret"
AUTH = {"Authorization": f"Bearer {TOKEN}"}

# What the shipped rules should say about the fixture: (rule, address, events, distinct usernames).
EXPECTED_ALERTS = [
    ("honeypot-credential-sweep", "203.0.113.90", 6, 6),  # six accounts tried from one address
    ("honeypot-file-transfer", "198.51.100.77", 2, None),  # one download that worked, one that failed
    ("honeypot-file-transfer", "203.0.113.45", 1, None),  # the SFTP upload
    ("honeypot-shell-commands", "198.51.100.77", 7, None),
]


def run(cli, *args):
    """Run a command-line entry point. Returns (stdout, stderr, exit code)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli(list(args))
        except SystemExit as exit_:
            code = exit_.code
    return out.getvalue(), err.getvalue(), code


def cowrie_line(seconds, eventid="cowrie.login.failed", ip="198.51.100.200", **fields):
    record = {"session": "feedfacecafe", "protocol": "ssh", "src_ip": ip, "src_port": 40000, "dst_ip": "192.0.2.10",
              "dst_port": 2222, "username": "root", "password": f"guess{seconds}"}  # fmt: skip
    record.update(fields)
    record.update({"eventid": eventid, "sensor": "honeypot01",
                   "timestamp": f"2026-10-12T10:{seconds // 60:02d}:{seconds % 60:02d}.000000Z", "message": ""})
    return json.dumps(record, separators=(",", ":")) + "\n"


def summary(alerts):
    return sorted((a.rule_id, a.group_key, a.event_count, a.distinct_count) for a in alerts)


class HoneypotTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.db = os.path.join(tmp.name, "honeypot.db")
        self.rules = load_rules(RULES_DIR)


class IngestCommandTests(HoneypotTestCase):
    def test_a_cowrie_log_is_ingested_without_a_year(self):
        out, err, code = run(ingest_cli, FIXTURE, "--source", "cowrie", "--db", self.db)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("66 lines -> 31 new events, 0 already stored, 35 ignored, 0 dead letters", out)
        self.assertNotIn("eventid:", out)  # the breakdown is only shown when asked for
        with EventStore(self.db) as store:
            self.assertEqual((store.count(), store.dead_letter_count()), (31, 0))
            self.assertEqual(store.event_type_counts(), {
                "connection": 10, "auth_success": 9, "command": 7, "file_transfer": 3, "auth_failure": 2,
            })  # fmt: skip
            (upload,) = [e for e in store.query(event_type=FILE_TRANSFER) if e.extra["direction"] == "upload"]
            self.assertEqual((upload.source, upload.src_ip, upload.extra["filename"]), ("cowrie", "203.0.113.45", "sshd"))
            self.assertEqual(len(upload.extra["shasum"]), 64)  # the file's hash survives storage, for looking it up

    def test_show_ignored_lists_what_was_left_out_and_why(self):
        out, _, code = run(ingest_cli, FIXTURE, "--source", "cowrie", "--db", self.db, "--show-ignored")
        self.assertEqual(code, 0)
        reasons = [line.split() for line in out.splitlines() if line.startswith("    ignored")]
        self.assertEqual(reasons[:3], [["ignored", "10", "eventid:cowrie.client.kex"],
                                       ["ignored", "10", "eventid:cowrie.client.version"],
                                       ["ignored", "10", "eventid:cowrie.session.closed"]])  # fmt: skip
        self.assertEqual(sum(int(count) for _, count, _ in reasons), 35)
        self.assertIn(["ignored", "1", "eventid:cowrie.direct-tcpip.request"], reasons)

    def test_an_sshd_log_still_needs_a_year_and_nothing_is_written_without_one(self):
        out, err, code = run(ingest_cli, FIXTURE, "--db", self.db)  # --source defaults to sshd
        self.assertEqual(code, 2)
        self.assertIn("--year is required for --source sshd", err)
        self.assertFalse(os.path.exists(self.db))

    def test_running_it_again_or_on_a_rotated_copy_adds_nothing(self):
        # Cowrie renames cowrie.json to cowrie.json.<date> each night, and old logs often get gzipped.
        rotated = os.path.join(self.dir, "cowrie.json.2026-10-12")
        zipped = os.path.join(self.dir, "cowrie.json.2026-10-12.gz")
        shutil.copy(FIXTURE, rotated)
        with open(FIXTURE, "rb") as source, gzip.open(zipped, "wb") as target:
            target.write(source.read())
        run(ingest_cli, FIXTURE, "--source", "cowrie", "--db", self.db)
        out, _, code = run(ingest_cli, FIXTURE, rotated, zipped, "--source", "cowrie", "--db", self.db)
        self.assertEqual(code, 0)
        self.assertEqual(out.count("66 lines -> 0 new events, 31 already stored"), 3)
        with EventStore(self.db) as store:
            self.assertEqual(store.count(), 31)

    def test_your_own_address_is_left_out(self):
        out, _, code = run(ingest_cli, FIXTURE, "--source", "cowrie", "--db", self.db, "--show-ignored",
                           "--ignore-ip", "198.51.100.77", "--ignore-ip", "203.0.113.44/31")  # fmt: skip
        self.assertEqual(code, 0)
        self.assertIn("66 lines -> 15 new events", out)  # 31, less 13 from one address and 3 from the other
        self.assertIn(["ignored", "16", "own-address"], [line.split() for line in out.splitlines()])
        with EventStore(self.db) as store:
            self.assertEqual(store.query(src_ip="198.51.100.77"), [])
            self.assertEqual(store.query(src_ip="203.0.113.45"), [])
            alerts = ReplayEngine(self.rules).run(store.iter_events())
        self.assertEqual(summary(alerts), [EXPECTED_ALERTS[0]])  # no alerts about yourself

    def test_a_mistyped_address_stops_the_run_before_anything_is_written(self):
        _, err, code = run(ingest_cli, FIXTURE, "--source", "cowrie", "--db", self.db, "--ignore-ip", "home")
        self.assertEqual(code, 2)
        self.assertIn("not an IP address or network: 'home'", err)
        self.assertFalse(os.path.exists(self.db))

    def test_the_text_log_is_not_mistaken_for_the_json_one(self):
        # Cowrie writes cowrie.log (text) next to cowrie.json. Feeding the wrong one must be obvious.
        text_log = os.path.join(self.dir, "cowrie.log")
        with open(text_log, "w") as fh:
            fh.write("2026-10-12T22:14:03.120394Z [HoneyPotSSHTransport,1,198.51.100.23] login attempt [root/x] succeeded\n" * 4)
        out, _, _ = run(ingest_cli, text_log, "--source", "cowrie", "--db", self.db)
        self.assertIn("4 lines -> 0 new events, 0 already stored, 0 ignored, 4 dead letters", out)
        with EventStore(self.db) as store:
            self.assertEqual({d.reason for d in store.dead_letters()}, {"not valid JSON"})


class DetectionTests(HoneypotTestCase):
    def ingest(self, path=FIXTURE):
        with EventStore(self.db) as store:
            ingest_file(path, CowrieParser(), store)

    def alerts(self):
        with EventStore(self.db) as store:
            return ReplayEngine(self.rules).run(store.iter_events())

    def test_the_shipped_rules_find_what_happened(self):
        self.ingest()
        alerts = self.alerts()
        self.assertEqual(summary(alerts), EXPECTED_ALERTS)
        self.assertEqual({a.rule_id: a.severity for a in alerts}, {
            "honeypot-file-transfer": "high", "honeypot-shell-commands": "medium", "honeypot-credential-sweep": "low",
        })  # fmt: skip

    def test_each_alert_points_at_the_events_behind_it(self):
        self.ingest()
        with EventStore(self.db) as store:
            alerts = ReplayEngine(self.rules).run(store.iter_events())
            store.sync_alerts(alerts, [rule.id for rule in self.rules])
            commands = next(a for a in alerts if a.rule_id == "honeypot-shell-commands")
            evidence = store.alert_events(commands.id)
        self.assertEqual({e.event_type for e in evidence}, {COMMAND})
        self.assertEqual([e.extra["input"] for e in evidence][:2], ["uname -a", "cat /proc/cpuinfo | grep name | wc -l"])
        self.assertEqual(evidence[-1].extra["input"], "exit")

    def test_a_scanner_that_only_connects_raises_nothing(self):
        self.ingest()
        self.assertNotIn("198.51.100.23", {a.group_key for a in self.alerts()})
        # ...and neither does logging in and leaving, which is what most visitors do.
        self.assertNotIn("198.51.100.140", {a.group_key for a in self.alerts()})

    def test_sshd_rules_do_not_read_honeypot_events(self):
        # Forty failed logins in a minute would trip ssh-brute-force on a real server. On the
        # honeypot it is not news, and nearly every guess "succeeds" anyway.
        log = os.path.join(self.dir, "cowrie.json")
        with open(log, "w") as fh:
            fh.writelines(cowrie_line(second) for second in range(40))
        self.ingest(log)
        self.assertEqual(self.alerts(), [])

    def test_honeypot_rules_do_not_read_sshd_events(self):
        dataset = simulated_dataset(7)
        fired = {a.rule_id for a in ReplayEngine(self.rules).run(dataset.events)}
        self.assertTrue(fired)
        self.assertFalse({rule_id for rule_id in fired if rule_id.startswith("honeypot-")})
        self.assertEqual(sorted(r.id for r in self.rules if r not in scored_rules(self.rules)),
                         ["honeypot-credential-sweep", "honeypot-file-transfer", "honeypot-shell-commands"])

    def test_one_visit_is_one_alert_and_a_return_visit_is_another(self):
        later = lambda line: line.replace("T10:", "T16:")  # noqa: E731
        upload = dict(ip="198.51.100.201", filename="f", shasum="ab" * 32)
        log = os.path.join(self.dir, "cowrie.json")
        with open(log, "w") as fh:
            # Commands 25 minutes apart, and files 50 minutes apart, are still the same visit...
            fh.writelines(cowrie_line(s, "cowrie.command.input", input=f"cmd {s}") for s in (0, 5, 1500, 3000))
            fh.writelines(cowrie_line(s, "cowrie.session.file_upload", **upload) for s in (0, 3000))
            # ...and the same two addresses six hours later are new ones.
            fh.write(later(cowrie_line(0, "cowrie.command.input", input="back again")))
            fh.write(later(cowrie_line(0, "cowrie.session.file_upload", **upload)))
        self.ingest(log)
        self.assertEqual(summary(self.alerts()), [
            ("honeypot-file-transfer", "198.51.100.201", 1, None), ("honeypot-file-transfer", "198.51.100.201", 2, None),
            ("honeypot-shell-commands", "198.51.100.200", 1, None), ("honeypot-shell-commands", "198.51.100.200", 4, None),
        ])  # fmt: skip

    def test_engine_command_saves_alerts_the_api_can_serve(self):
        run(ingest_cli, FIXTURE, "--source", "cowrie", "--db", self.db)
        out, err, code = run(engine_cli, "--db", self.db, "--rules", RULES_DIR, "--save")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("4 alert(s) from 8 rule(s)", out)
        self.assertIn("saved: 4 new", out)

        client = TestClient(create_app(self.db, self.rules, TOKEN))
        alerts = client.get("/alerts", headers=AUTH).json()["alerts"]
        self.assertEqual(sorted((a["rule_id"], a["group_key"]) for a in alerts), [e[:2] for e in EXPECTED_ALERTS])
        transfer = next(a for a in alerts if (a["rule_id"], a["group_key"]) == ("honeypot-file-transfer", "198.51.100.77"))
        detail = client.get(f"/alerts/{transfer['id']}", headers=AUTH).json()
        self.assertEqual([(e["outcome"], e["extra"]["url"]) for e in detail["evidence"]], [
            ("success", "http://203.0.113.200/bins/x86"), ("failure", "http://203.0.113.200/bins/arm7"),
        ])  # fmt: skip
        page = client.get("/events", headers=AUTH, params={"event_type": "command"}).json()
        self.assertEqual((page["total"], {e["source"] for e in page["events"]}), (7, {"cowrie"}))
        self.assertEqual(client.get("/stats", headers=AUTH).json()["events"]["by_type"]["file_transfer"], 3)
        hits = {r["id"]: r["alerts"] for r in client.get("/rules", headers=AUTH).json()}
        self.assertEqual((hits["honeypot-file-transfer"], hits["ssh-brute-force"]), (2, 0))


class Clock:
    now = 0.0

    def __call__(self):
        return self.now


class WatchTests(HoneypotTestCase):
    def test_following_a_cowrie_log_raises_alerts_as_lines_arrive(self):
        log = os.path.join(self.dir, "cowrie.json")
        open(log, "w").close()
        clock = Clock()
        with open(FIXTURE) as fh:
            lines = fh.readlines()
        with EventStore(self.db) as store:
            watcher = Watcher([log], store, self.rules, lambda: build_parser("cowrie"), lateness=2.0, clock=clock)
            watcher.start()
            with open(log, "a") as fh:
                fh.writelines(lines[:10])  # the scanner, then the bot up to its upload
            watcher.step()
            clock.now += 2.0
            (opened,) = watcher.step().opened
            self.assertEqual((opened.rule_id, opened.group_key), ("honeypot-file-transfer", "203.0.113.45"))

            with open(log, "a") as fh:
                fh.writelines(lines[10:])
            watcher.step()
            clock.now += 2.0
            report = watcher.step()
            watcher.close()
            self.assertEqual(sorted((a.rule_id, a.group_key) for a in report.opened), [e[:2] for e in EXPECTED_ALERTS
                                                                                     if e[1] != "203.0.113.45"])
            self.assertEqual(summary(s.alert for s in store.list_alerts()), EXPECTED_ALERTS)

            # Stopping and starting again picks up where it left off: nothing re-read, nothing re-raised.
            again = Watcher([log], store, self.rules, lambda: build_parser("cowrie"), lateness=2.0, clock=clock)
            restarted = again.start()
            again.close()
            self.assertEqual((restarted.new, restarted.updated, store.count()), (0, 0, 31))

    def test_watch_command_needs_no_year_for_cowrie(self):
        out, err, code = run(watch_cli, FIXTURE, "--source", "cowrie", "--db", self.db, "--rules", RULES_DIR, "--once")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("caught up: 31 events stored, 4 alert(s) (4 new, 0 updated, 0 reopened)", out)

        mine = self.db + ".mine"
        out, _, code = run(watch_cli, FIXTURE, "--source", "cowrie", "--db", mine, "--rules", RULES_DIR, "--once",
                           "--ignore-ip", "198.51.100.77")  # fmt: skip
        self.assertEqual(code, 0)
        self.assertIn("caught up: 18 events stored, 2 alert(s)", out)

        _, err, code = run(watch_cli, FIXTURE, "--db", self.db + ".other", "--rules", RULES_DIR, "--once")
        self.assertEqual(code, 2)
        self.assertIn("--year is required for --source sshd", err)
        self.assertFalse(os.path.exists(self.db + ".other"))


if __name__ == "__main__":
    unittest.main()
