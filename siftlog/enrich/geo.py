"""GeoIP enrichment: attach an approximate location to an event's source address.

Only an offline database is ever used: no API calls, so no rate limits and no
leaking which addresses are being investigated.

A resolver is anything with ``lookup(ip) -> dict or None``. The dict has ``lat``
and ``lon`` and may have ``country``, ``city`` and ``accuracy_km``.

GeoIP is approximate and easy to defeat: VPNs, mobile carriers and carrier-grade
NAT all put a user somewhere they are not. Location-based rules should be read
as "worth a look", never as proof.
"""
from __future__ import annotations

import math
from dataclasses import replace
from typing import Any, Dict, Mapping, Optional, Protocol

from siftlog.events import Event

EARTH_RADIUS_KM = 6371.0


class GeoResolver(Protocol):
    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        ...


class TableGeoResolver:
    """Lookups from a fixed table. Used for the simulator, whose documentation
    addresses appear in no real GeoIP database, and to keep tests offline."""

    def __init__(self, table: Mapping[str, Mapping[str, Any]]) -> None:
        self._table = table

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        entry = self._table.get(ip)
        return dict(entry) if entry is not None else None


class MaxMindGeoResolver:
    """Adapter over a MaxMind DB reader holding GeoLite2-City or a compatible database.

    The reader is injected, so the record-to-dict mapping is tested without the
    database, which cannot be redistributed. Use ``open_maxmind`` for a real file.
    """

    def __init__(self, reader: Any) -> None:
        self._reader = reader

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            record = self._reader.get(ip)
        except ValueError:  # not an IP address
            return None
        if not isinstance(record, dict):
            return None
        location = record.get("location") or {}
        lat, lon = location.get("latitude"), location.get("longitude")
        if lat is None or lon is None:
            return None  # the database knows the network but not where it is
        geo: Dict[str, Any] = {"lat": float(lat), "lon": float(lon)}
        country = (record.get("country") or {}).get("iso_code")
        if country:
            geo["country"] = country
        city = ((record.get("city") or {}).get("names") or {}).get("en")
        if city:
            geo["city"] = city
        if location.get("accuracy_radius") is not None:
            geo["accuracy_km"] = location["accuracy_radius"]
        return geo


def open_maxmind(path: str) -> MaxMindGeoResolver:
    """Open a GeoLite2-City ``.mmdb`` file. Needs the optional ``maxminddb`` package."""
    try:
        import maxminddb
    except ImportError as exc:
        raise RuntimeError("GeoLite2 lookups need the 'maxminddb' package: pip install maxminddb") from exc
    return MaxMindGeoResolver(maxminddb.open_database(path))


def enrich(event: Event, resolver: GeoResolver) -> Event:
    """Return ``event`` with ``geo`` filled in when the address can be located."""
    if event.src_ip is None or event.geo is not None:
        return event
    geo = resolver.lookup(event.src_ip)
    return event if geo is None else replace(event, geo=geo)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points, in kilometres."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(h)))
