"""Timestamp parsing shared by the parsers."""
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

_ISO = re.compile(r"(?P<dt>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?(?P<tz>Z|[+-]\d{2}:?\d{2})")


def iso_to_utc(dt: str, fraction: Optional[str], zone: str) -> datetime:
    """Combine the pieces of an ISO 8601 timestamp into an aware UTC datetime.

    Raises ValueError for an impossible date or offset.
    """
    base = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
    microsecond = int((fraction[1:] + "000000")[:6]) if fraction else 0
    if zone == "Z":
        offset = timedelta(0)
    else:
        digits = zone[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        if zone[0] == "-":
            offset = -offset
    return base.replace(microsecond=microsecond, tzinfo=timezone(offset)).astimezone(timezone.utc)


def parse_iso(text: object) -> datetime:
    """Parse a whole string such as ``2026-10-13T03:31:04.392325Z``. An offset is required."""
    match = _ISO.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise ValueError(f"not an ISO 8601 timestamp with an offset: {text!r}"[:120])
    return iso_to_utc(match.group("dt"), match.group("frac"), match.group("tz"))
