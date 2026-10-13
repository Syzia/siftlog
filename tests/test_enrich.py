import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from siftlog.enrich import MaxMindGeoResolver, TableGeoResolver, enrich, haversine_km, open_maxmind
from siftlog.enrich.__main__ import main as enrich_cli
from siftlog.events import AUTH_SUCCESS, Event, make_event_id
from siftlog.simulator import FAKE_GEO
from siftlog.store import EventStore

T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)
LONDON = {"lat": 51.5074, "lon": -0.1278, "country": "GB", "city": "London"}
TABLE = {"198.51.100.10": LONDON}


def event(n, ip="198.51.100.10", geo=None):
    return Event(id=make_event_id("t", n), timestamp=T0 + timedelta(seconds=n), source="sshd",
                 event_type=AUTH_SUCCESS, src_ip=ip, username="carol", host="h", outcome="success",
                 raw="", geo=geo, source_id="t", offset=n)


class FakeReader:
    """Stands in for a MaxMind DB reader; records are shaped like GeoLite2-City."""

    def __init__(self, records):
        self.records = records

    def get(self, ip):
        if ip == "not-an-ip":
            raise ValueError("'not-an-ip' does not appear to be an IPv4 or IPv6 address")
        return self.records.get(ip)


class ResolverTests(unittest.TestCase):
    def test_table_resolver(self):
        resolver = TableGeoResolver(TABLE)
        self.assertEqual(resolver.lookup("198.51.100.10"), LONDON)
        self.assertIsNone(resolver.lookup("203.0.113.1"))
        resolver.lookup("198.51.100.10")["city"] = "changed"  # callers get a copy
        self.assertEqual(TABLE["198.51.100.10"]["city"], "London")

    def test_maxmind_record_is_flattened(self):
        reader = FakeReader({
            "198.51.100.10": {
                "country": {"iso_code": "GB", "names": {"en": "United Kingdom"}},
                "city": {"names": {"en": "London", "fr": "Londres"}},
                "location": {"latitude": 51.5074, "longitude": -0.1278, "accuracy_radius": 20},
            },
        })  # fmt: skip
        self.assertEqual(
            MaxMindGeoResolver(reader).lookup("198.51.100.10"),
            {"lat": 51.5074, "lon": -0.1278, "country": "GB", "city": "London", "accuracy_km": 20},
        )

    def test_maxmind_partial_and_missing_records(self):
        reader = FakeReader({
            "country-only": {"country": {"iso_code": "AU"}, "location": {"latitude": -25.0, "longitude": 135.0}},
            "no-location": {"country": {"iso_code": "US"}},
            "half-location": {"location": {"latitude": 10.0}},
            "empty": {},
        })  # fmt: skip
        resolver = MaxMindGeoResolver(reader)
        self.assertEqual(resolver.lookup("country-only"), {"lat": -25.0, "lon": 135.0, "country": "AU"})
        for ip in ("no-location", "half-location", "empty", "unknown", "not-an-ip"):
            with self.subTest(ip=ip):
                self.assertIsNone(resolver.lookup(ip))

    @unittest.skipIf(importlib.util.find_spec("maxminddb") is not None, "maxminddb is installed")
    def test_opening_a_real_database_needs_the_optional_package(self):
        with self.assertRaises(RuntimeError) as caught:
            open_maxmind("/nonexistent.mmdb")
        self.assertIn("pip install maxminddb", str(caught.exception))


class EnrichTests(unittest.TestCase):
    def test_fills_location_when_known(self):
        self.assertEqual(enrich(event(1), TableGeoResolver(TABLE)).geo, LONDON)

    def test_leaves_events_it_cannot_improve_untouched(self):
        resolver = TableGeoResolver(TABLE)
        unknown, no_address, already = event(1, ip="203.0.113.1"), event(2, ip=None), event(3, geo={"lat": 1.0, "lon": 2.0})
        for e in (unknown, no_address, already):
            self.assertIs(enrich(e, resolver), e)

    def test_haversine(self):
        self.assertAlmostEqual(haversine_km(51.5074, -0.1278, 40.7128, -74.0060), 5570, delta=20)  # London - New York
        self.assertEqual(haversine_km(10.0, 20.0, 10.0, 20.0), 0.0)
        self.assertAlmostEqual(haversine_km(0, 0, 0, 180), 20015, delta=5)  # half the equator
        self.assertAlmostEqual(haversine_km(51.5, -0.1, -33.9, 151.2), haversine_km(-33.9, 151.2, 51.5, -0.1))


class BackfillTests(unittest.TestCase):
    def test_backfill_locates_only_events_without_a_location(self):
        kept = {"lat": 1.0, "lon": 2.0}
        with EventStore() as store:
            store.add_events([event(1), event(2), event(3, ip="203.0.113.1"), event(4, geo=kept), event(5, ip=None)])
            self.assertEqual(store.backfill_geo(TableGeoResolver(TABLE)), (2, 1))  # 2 events, 1 address
            by_offset = {e.offset: e.geo for e in store.query()}
            self.assertEqual(by_offset, {1: LONDON, 2: LONDON, 3: None, 4: kept, 5: None})
            self.assertEqual(store.backfill_geo(TableGeoResolver(TABLE)), (0, 0))  # nothing left to do

    def test_reingesting_does_not_erase_locations(self):
        with EventStore() as store:
            store.add_events([event(1)])
            store.backfill_geo(TableGeoResolver(TABLE))
            store.add_events([event(1)])  # the same event again, with no location
            self.assertEqual(store.query()[0].geo, LONDON)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "e.db")
            with EventStore(db) as store:
                store.add_events([event(1, ip=ip) for ip in ("198.51.100.10",)] + [event(2, ip="203.0.113.50")])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(enrich_cli(["--db", db, "--simulated"]), 0)
            self.assertIn("located 2 event(s) across 2 address(es)", out.getvalue())
            with EventStore(db) as store:
                self.assertEqual([e.geo for e in store.query()],
                                 [dict(FAKE_GEO["198.51.100.10"]), dict(FAKE_GEO["203.0.113.50"])])

            # A source of locations is required, and a database that cannot be opened is a clean error.
            for argv in (["--db", db], ["--db", db, "--geoip", os.path.join(tmp, "missing.mmdb")]):
                with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as stop:
                        enrich_cli(argv)
                    self.assertEqual(stop.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
