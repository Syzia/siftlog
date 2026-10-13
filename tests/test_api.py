"""Stage 5 acceptance: API tests cover every endpoint."""
import contextlib
import io
import os
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from fastapi.testclient import TestClient

from siftlog.api import create_app
from siftlog.api.__main__ import TOKEN_ENV, build
from siftlog.enrich import TableGeoResolver
from siftlog.engine import ReplayEngine, load_rules
from siftlog.ingest import ingest_file
from siftlog.parsers import SshdParser
from siftlog.simulator import FAKE_GEO, load_labels, simulate, write_files
from siftlog.store import EventStore

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
TOKEN = "test-token-not-a-real-secret"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PROTECTED = [("GET", "/alerts"), ("GET", "/alerts/abc"), ("PATCH", "/alerts/abc"),
             ("GET", "/events"), ("GET", "/stats"), ("GET", "/rules")]  # fmt: skip


class ApiTestCase(unittest.TestCase):
    """One simulated world, ingested, located, detected and saved once; each test gets a copy."""

    @classmethod
    def setUpClass(cls):
        cls._base = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._base.cleanup)
        log = os.path.join(cls._base.name, "sim.log")
        labels_path = os.path.join(cls._base.name, "sim.labels.json")
        cls._base_db = os.path.join(cls._base.name, "base.db")
        write_files(simulate(seed=1234), log, labels_path)
        cls.labels = {label.kind: label for label in load_labels(labels_path)}
        cls.rules = load_rules(RULES_DIR)
        with EventStore(cls._base_db) as store:
            ingest_file(log, SshdParser(year=2026), store)
            store.backfill_geo(TableGeoResolver(FAKE_GEO))
            store.sync_alerts(ReplayEngine(cls.rules).run(store.iter_events()), [r.id for r in cls.rules])

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = os.path.join(tmp.name, "events.db")
        shutil.copy(self._base_db, self.db)
        self.client = TestClient(create_app(self.db, self.rules, TOKEN))

    def get(self, url, **params):
        return self.client.get(url, headers=AUTH, params=params)

    def alerts(self, **params):
        response = self.get("/alerts", **params)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def alert_for(self, kind):
        """The stored alert for a simulated scenario's main expected rule."""
        label = self.labels[kind]
        (found,) = self.alerts(rule_id=label.rule_hint, group_key=label.group_key)["alerts"]
        return found


class AuthTests(ApiTestCase):
    def test_health_needs_no_token_and_says_nothing(self):
        response = self.client.get("/health")
        self.assertEqual((response.status_code, response.json()), (200, {"status": "ok"}))

    def test_the_bare_address_leads_to_the_documentation(self):
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual((response.status_code, response.headers["location"]), (307, "/docs"))
        self.assertEqual(self.client.get("/").status_code, 200)  # following it reaches the docs page
        self.assertIn("swagger", self.client.get("/docs").text.lower())

    def test_every_other_route_refuses_without_the_token(self):
        attempts = {
            "no header": {},
            "wrong token": {"Authorization": "Bearer nope"},
            "wrong scheme": {"Authorization": f"Basic {TOKEN}"},
            "empty token": {"Authorization": "Bearer "},
            "token prefix": {"Authorization": f"Bearer {TOKEN[:-1]}"},
            "non-ascii": {"Authorization": "Bearer café".encode("utf-8")},
        }
        for method, url in PROTECTED:
            for name, headers in attempts.items():
                with self.subTest(method=method, url=url, attempt=name):
                    response = self.client.request(method, url, headers=headers, json={"status": "ack"})
                    self.assertEqual(response.status_code, 401, response.text)
                    self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_token_in_the_query_string_is_not_accepted(self):
        self.assertEqual(self.client.get("/alerts", params={"token": TOKEN}).status_code, 401)

    def test_an_app_cannot_be_built_without_a_token(self):
        with self.assertRaises(ValueError):
            create_app(self.db, self.rules, "")

    def test_responses_carry_defensive_headers(self):
        for response in (self.client.get("/health"), self.get("/alerts"), self.client.get("/alerts")):
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(response.headers["cache-control"], "no-store")

    def test_openapi_documents_the_bearer_scheme(self):
        spec = self.client.get("/openapi.json").json()
        self.assertEqual(sorted(spec["paths"]), ["/alerts", "/alerts/{alert_id}", "/events", "/health", "/rules", "/stats"])
        self.assertIn("security", spec["paths"]["/alerts"]["get"])
        self.assertNotIn("security", spec["paths"]["/health"]["get"])


class AlertListTests(ApiTestCase):
    def test_lists_every_alert_newest_activity_first(self):
        page = self.alerts()
        self.assertEqual((page["total"], page["limit"], page["offset"], len(page["alerts"])), (7, 100, 0, 7))
        stamps = [a["last_seen"] for a in page["alerts"]]
        self.assertEqual(stamps, sorted(stamps, reverse=True))
        self.assertEqual({a["status"] for a in page["alerts"]}, {"open"})
        expected = {pair for label in self.labels.values() for pair in label.expected_alerts}
        self.assertEqual({(a["rule_id"], a["group_key"]) for a in page["alerts"]},
                         expected | {("ssh-impossible-travel", "vera")})

    def test_filters(self):
        self.assertEqual(self.alerts(rule_id="ssh-brute-force")["total"], 2)
        self.assertEqual(self.alerts(severity="critical")["total"], 1)
        self.assertEqual(self.alerts(group_key="carol")["alerts"][0]["rule_id"], "ssh-impossible-travel")
        self.assertEqual(self.alerts(status="closed")["total"], 0)
        self.assertEqual(self.alerts(rule_id="no-such-rule")["total"], 0)

    def test_time_filters_treat_a_bare_timestamp_as_utc(self):
        brute = self.alert_for("brute_force")
        bare = brute["first_seen"].replace("Z", "").replace("+00:00", "")
        with_offset = self.alerts(since=brute["first_seen"], until=brute["last_seen"])
        self.assertEqual(self.alerts(since=bare, until=brute["last_seen"]), with_offset)
        self.assertIn(brute["id"], [a["id"] for a in with_offset["alerts"]])
        self.assertEqual(self.alerts(since="2030-01-01T00:00:00Z")["total"], 0)

    def test_paging_is_consistent(self):
        everything = [a["id"] for a in self.alerts()["alerts"]]
        first, second = self.alerts(limit=3), self.alerts(limit=3, offset=3)
        self.assertEqual((first["total"], second["total"]), (7, 7))
        self.assertEqual([a["id"] for a in first["alerts"] + second["alerts"]], everything[:6])

    def test_bad_parameters_are_rejected_not_guessed(self):
        bad = [{"status": "ignored"}, {"severity": "urgent"}, {"limit": 0}, {"limit": 1001}, {"offset": -1},
               {"since": "yesterday"}, {"rule_id": "x" * 201}, {"include_superseded": "maybe"}]  # fmt: skip
        for params in bad:
            with self.subTest(params=params):
                self.assertEqual(self.get("/alerts", **params).status_code, 422)

    def test_hostile_parameters_are_just_values(self):
        for value in ("' OR '1'='1", "x'; DROP TABLE alerts; --", "%", "<script>alert(1)</script>"):
            with self.subTest(value=value):
                self.assertEqual(self.alerts(group_key=value)["total"], 0)
                self.assertEqual(self.alerts(rule_id=value)["total"], 0)
        self.assertEqual(self.alerts()["total"], 7)  # still there


class AlertDetailTests(ApiTestCase):
    def test_detail_carries_evidence_and_history(self):
        summary = self.alert_for("brute_force")
        detail = self.get(f"/alerts/{summary['id']}").json()
        self.assertEqual({k: detail[k] for k in summary}, summary)
        self.assertEqual((detail["evidence_total"], len(detail["evidence"]), detail["history"]), (40, 40, []))
        attacker = self.labels["brute_force"].group_key
        self.assertEqual({e["src_ip"] for e in detail["evidence"]}, {attacker})
        self.assertEqual({e["event_type"] for e in detail["evidence"]}, {"auth_failure"})
        self.assertTrue(all("Failed password" in e["raw"] for e in detail["evidence"]))
        stamps = [e["timestamp"] for e in detail["evidence"]]
        self.assertEqual(stamps, sorted(stamps))

    def test_evidence_can_be_limited(self):
        alert_id = self.alert_for("brute_force")["id"]
        detail = self.get(f"/alerts/{alert_id}", evidence_limit=5).json()
        self.assertEqual((detail["evidence_total"], len(detail["evidence"])), (40, 5))
        self.assertEqual(self.get(f"/alerts/{alert_id}", evidence_limit=0).json()["evidence"], [])
        self.assertEqual(self.get(f"/alerts/{alert_id}", evidence_limit=5000).status_code, 422)

    def test_travel_alert_explains_itself_and_its_evidence_is_located(self):
        detail = self.get(f"/alerts/{self.alert_for('impossible_travel')['id']}").json()
        self.assertIn("London -> Sydney", detail["summary"])
        self.assertEqual([e["geo"]["city"] for e in detail["evidence"]], ["London", "Sydney"])

    def test_unknown_alert(self):
        self.assertEqual(self.get("/alerts/does-not-exist").status_code, 404)
        self.assertEqual(self.get("/alerts/" + "a" * 65).status_code, 422)


class WorkflowTests(ApiTestCase):
    def patch(self, alert_id, **body):
        return self.client.patch(f"/alerts/{alert_id}", headers=AUTH, json=body)

    def test_acknowledge_then_close(self):
        alert_id = self.alert_for("password_spray")["id"]
        acked = self.patch(alert_id, status="ack", note="blocking the address")
        self.assertEqual(acked.status_code, 200, acked.text)
        self.assertEqual((acked.json()["status"], acked.json()["note"]), ("ack", "blocking the address"))
        self.assertIsNotNone(acked.json()["status_changed_at"])
        self.assertEqual(self.patch(alert_id, status="closed", note="blocked").json()["status"], "closed")

        history = self.get(f"/alerts/{alert_id}").json()["history"]
        self.assertEqual([(h["old_status"], h["new_status"], h["actor"], h["note"]) for h in history],
                         [("open", "ack", "api", "blocking the address"), ("ack", "closed", "api", "blocked")])
        self.assertEqual(self.alerts(status="closed")["total"], 1)
        self.assertEqual(self.alerts(status="open")["total"], 6)

    def test_decisions_persist_across_restarts_and_replays(self):
        alert_id = self.alert_for("credential_stuffing")["id"]
        self.patch(alert_id, status="ack", note="ticket 42")
        with EventStore(self.db) as store:  # the engine runs again, as `--save` would
            report = store.sync_alerts(ReplayEngine(self.rules).run(store.iter_events()), [r.id for r in self.rules])
        self.assertEqual((report.unchanged, report.new, report.removed), (7, 0, 0))
        restarted = TestClient(create_app(self.db, self.rules, TOKEN))
        again = restarted.get(f"/alerts/{alert_id}", headers=AUTH).json()
        self.assertEqual((again["status"], again["note"]), ("ack", "ticket 42"))

    def test_bad_updates_are_rejected(self):
        alert_id = self.alert_for("brute_force")["id"]
        for body in ({"status": "ignored"}, {}, {"status": "ack", "severity": "low"},
                     {"status": "ack", "note": "x" * 2001}, {"status": None}, {"note": "no status"}):  # fmt: skip
            with self.subTest(body=body):
                self.assertEqual(self.patch(alert_id, **body).status_code, 422)
        self.assertEqual(self.get(f"/alerts/{alert_id}").json()["status"], "open")  # nothing changed
        self.assertEqual(self.patch("does-not-exist", status="ack").status_code, 404)

    def test_a_hostile_note_is_stored_and_returned_as_text(self):
        alert_id = self.alert_for("brute_force")["id"]
        note = "<script>alert(1)</script> '; DROP TABLE alerts; --"
        response = self.patch(alert_id, status="ack", note=note)
        self.assertEqual(response.json()["note"], note)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(self.alerts()["total"], 7)


class EventTests(ApiTestCase):
    def test_search_by_address(self):
        attacker = self.labels["brute_force"].group_key
        page = self.get("/events", src_ip=attacker, event_type="auth_failure").json()
        self.assertEqual((page["total"], len(page["events"])), (40, 40))
        self.assertEqual({e["src_ip"] for e in page["events"]}, {attacker})

    def test_limit_caps_the_page_but_not_the_total(self):
        page = self.get("/events", event_type="auth_failure", limit=5).json()
        self.assertEqual(len(page["events"]), 5)
        self.assertGreater(page["total"], 300)
        self.assertEqual(self.get("/events", limit=1001).status_code, 422)
        self.assertEqual(self.get("/events", limit=0).status_code, 422)

    def test_order_and_time_window(self):
        oldest = self.get("/events", limit=3).json()["events"]
        newest = self.get("/events", limit=3, newest_first=True).json()["events"]
        self.assertLess(oldest[0]["timestamp"], newest[0]["timestamp"])
        self.assertEqual([e["timestamp"] for e in newest], sorted((e["timestamp"] for e in newest), reverse=True))
        label = self.labels["brute_force"]
        inside = self.get("/events", src_ip=label.group_key, since=label.start.isoformat(),
                          until=label.start.isoformat()).json()
        self.assertEqual(inside["total"], 0)  # until is exclusive, so an empty window

    def test_hostile_and_malformed_parameters(self):
        for value in ("' OR '1'='1", "203.0.113.1; DROP TABLE events", "%"):
            with self.subTest(value=value):
                self.assertEqual(self.get("/events", src_ip=value).json()["total"], 0)
                self.assertEqual(self.get("/events", username=value).json()["total"], 0)
        self.assertEqual(self.get("/events", src_ip="1" * 65).status_code, 422)
        self.assertEqual(self.get("/events", since="not-a-date").status_code, 422)
        self.assertGreater(self.get("/events").json()["total"], 600)


class StatsAndRulesTests(ApiTestCase):
    def test_stats_agree_with_the_store(self):
        stats = self.get("/stats").json()
        with EventStore(self.db) as store:
            self.assertEqual(stats["events"]["total"], store.count())
            self.assertEqual(stats["events"]["by_type"], store.event_type_counts())
            self.assertEqual(stats["events"]["dead_letters"], 0)
        self.assertEqual(sum(stats["events"]["by_type"].values()), stats["events"]["total"])
        self.assertLess(stats["events"]["first"], stats["events"]["last"])
        self.assertEqual(stats["alerts"]["total"], 7)
        self.assertEqual(stats["alerts"]["by_status"], {"open": 7})
        self.assertEqual(stats["alerts"]["by_severity"], {"critical": 1, "high": 6})
        self.assertEqual(sum(stats["alerts"]["by_rule"].values()), 7)
        self.assertEqual(sum(day["alerts"] for day in stats["alerts_over_time"]), 7)

    def test_the_busiest_source_is_the_attack_the_rules_miss(self):
        # No rule fires on the low-and-slow attacker, but it tops the failure count:
        # the stats give an analyst a second way to find it.
        top = self.get("/stats").json()["top_sources"]
        self.assertEqual(top[0], {"src_ip": self.labels["low_and_slow"].group_key, "failures": 144})
        self.assertEqual([s["failures"] for s in top], sorted((s["failures"] for s in top), reverse=True))
        self.assertLessEqual(len(top), 10)

    def test_stats_follow_decisions(self):
        alert_id = self.alert_for("brute_force")["id"]
        self.client.patch(f"/alerts/{alert_id}", headers=AUTH, json={"status": "closed"})
        self.assertEqual(self.get("/stats").json()["alerts"]["by_status"], {"closed": 1, "open": 6})

    def test_rules_listing_with_hit_counts(self):
        rules = {r["id"]: r for r in self.get("/rules").json()}
        self.assertEqual(set(rules), {r.id for r in self.rules})
        self.assertEqual({k: v["alerts"] for k, v in rules.items()}, {
            "ssh-brute-force": 2, "ssh-credential-stuffing": 1, "ssh-impossible-travel": 2,
            "ssh-password-spray": 1, "ssh-success-after-failures": 1,
        })  # fmt: skip
        brute = rules["ssh-brute-force"]
        self.assertEqual((brute["type"], brute["group_by"], brute["timespan_seconds"], brute["mitre"]),
                         ("event_count", ["src_ip"], 300, ["T1110.001"]))
        self.assertTrue(all(r["description"] for r in rules.values()))


class ConcurrencyTests(ApiTestCase):
    def test_parallel_requests_each_get_their_own_connection(self):
        app = create_app(self.db, self.rules, TOKEN)  # one app, many threads, as under uvicorn

        def hit(n):
            url = ("/alerts", "/stats", "/events?limit=5", "/rules")[n % 4]
            return TestClient(app).get(url, headers=AUTH).status_code

        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(set(pool.map(hit, range(40))), {200})


class CliTests(ApiTestCase):
    def build(self, *argv, env=None):
        environment = {k: v for k, v in os.environ.items() if k != TOKEN_ENV}
        environment.update(env or {})
        err = io.StringIO()
        with mock.patch.dict(os.environ, environment, clear=True), contextlib.redirect_stderr(err):
            return build(["--db", self.db, "--rules", RULES_DIR, *argv]), err.getvalue()

    def test_generates_a_token_when_none_is_set(self):
        (app, host, port), printed = self.build()
        self.assertEqual((host, port), ("127.0.0.1", 8000))
        token = printed.strip().rsplit(" ", 1)[-1]
        self.assertGreaterEqual(len(token), 32)
        client = TestClient(app)
        self.assertEqual(client.get("/alerts", headers={"Authorization": f"Bearer {token}"}).status_code, 200)
        self.assertEqual(client.get("/alerts", headers=AUTH).status_code, 401)

    def test_uses_the_configured_token_and_does_not_print_it(self):
        (app, _, _), printed = self.build(env={TOKEN_ENV: TOKEN})
        self.assertNotIn(TOKEN, printed)
        self.assertEqual(TestClient(app).get("/alerts", headers=AUTH).status_code, 200)

    def test_refuses_to_leave_loopback_with_a_generated_token(self):
        with self.assertRaises(SystemExit) as stop:
            self.build("--host", "0.0.0.0")
        self.assertEqual(stop.exception.code, 2)
        (_, host, _), printed = self.build("--host", "0.0.0.0", env={TOKEN_ENV: TOKEN})
        self.assertEqual(host, "0.0.0.0")
        self.assertIn("plain HTTP", printed)

    def test_missing_database_or_rules_is_an_error_not_an_empty_server(self):
        missing = os.path.join(os.path.dirname(self.db), "missing.db")
        for argv in (["--db", missing, "--rules", RULES_DIR], ["--db", self.db, "--rules", missing]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stop:
                    build(argv)
                self.assertEqual(stop.exception.code, 2)
        self.assertFalse(os.path.exists(missing))


if __name__ == "__main__":
    unittest.main()
