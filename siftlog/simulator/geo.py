"""Fake GeoIP table for the simulator and for tests.

The simulator only uses RFC 5737 documentation addresses, which no real GeoIP
database contains. Impossible-travel detection (stage 4) therefore needs this
stand-in. It also keeps CI independent of the MaxMind database, which cannot be
redistributed.
"""
from __future__ import annotations

from typing import Any, Dict

LONDON_IP = "198.51.100.10"
NEW_YORK_IP = "198.51.100.20"
SYDNEY_IP = "203.0.113.50"
OFFICE_IP = "192.0.2.10"

FAKE_GEO: Dict[str, Dict[str, Any]] = {
    LONDON_IP: {"country": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278},
    NEW_YORK_IP: {"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    SYDNEY_IP: {"country": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
    OFFICE_IP: {"country": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278},
}
