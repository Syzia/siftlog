"""Helpers shared by the event and alert halves of the store."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MICROSECOND = timedelta(microseconds=1)


class StoreError(Exception):
    """The database is not one this version of Siftlog can safely use."""


def to_micros(dt: datetime) -> int:
    """Timestamps are stored as integer microseconds since the Unix epoch, UTC."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return (dt.astimezone(timezone.utc) - _EPOCH) // _MICROSECOND


def from_micros(micros: int) -> datetime:
    return _EPOCH + timedelta(microseconds=micros)


def to_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def check_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("limit must be a non-negative integer")
    return limit
