"""SQLite event store.

Design notes:

* **Idempotent writes.** ``events.id`` is unique and inserts are ``OR IGNORE``,
  so ingesting the same data twice changes nothing.
* **Timestamps are integer microseconds since the Unix epoch (UTC).** Exact,
  compact, and range queries are plain integer comparisons.
* **Every query is parameterised.** Usernames and similar fields are
  attacker-controlled log content; values never reach the SQL text. Column names
  and sort direction come from fixed strings in this module.
* **Order is deterministic:** ``(timestamp, source_id, byte_offset)``, i.e. time
  first, then file order within a stream.
* One connection per store, not shared across threads. The API (stage 5) will
  open its own.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from siftlog.events import AUTH_FAILURE, DeadLetter, Event
from siftlog.store._common import StoreError
from siftlog.store._common import check_limit as _check_limit
from siftlog.store._common import from_micros as _from_micros
from siftlog.store._common import to_json as _json
from siftlog.store._common import to_micros as _to_micros
from siftlog.store.alerts import ALERT_SCHEMA, AlertStoreMixin

# 1: events and dead letters. 2: adds alerts, their evidence and their status history.
SCHEMA_VERSION = 2

# byte_offset / repeat_count rather than offset / count: OFFSET is an SQL keyword
# and COUNT is an aggregate, both confusing as bare column names.
_SCHEMA = """
CREATE TABLE events (
    id           TEXT    NOT NULL UNIQUE,
    ts           INTEGER NOT NULL,
    source       TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    src_ip       TEXT,
    username     TEXT,
    host         TEXT,
    outcome      TEXT,
    repeat_count INTEGER NOT NULL DEFAULT 1,
    geo          TEXT,
    extra        TEXT    NOT NULL,
    raw          TEXT    NOT NULL,
    source_id    TEXT    NOT NULL,
    byte_offset  INTEGER NOT NULL
);
-- Nearly every rule is a windowed query on one of these.
CREATE INDEX idx_events_src_ip_ts ON events (src_ip, ts);
CREATE INDEX idx_events_username_ts ON events (username, ts);
-- Replay mode scans a time range regardless of who.
CREATE INDEX idx_events_ts ON events (ts);

CREATE TABLE dead_letters (
    source_id   TEXT    NOT NULL,
    byte_offset INTEGER NOT NULL,
    raw         TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    PRIMARY KEY (source_id, byte_offset)
);
"""

_COLUMNS = (
    "id, ts, source, event_type, src_ip, username, host, outcome, "
    "repeat_count, geo, extra, raw, source_id, byte_offset"
)
_INSERT_EVENT = f"INSERT OR IGNORE INTO events ({_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
_INSERT_DEAD = (
    "INSERT OR IGNORE INTO dead_letters (source_id, byte_offset, raw, reason) VALUES (?,?,?,?)"
)
_ORDER = {False: "ORDER BY ts, source_id, byte_offset", True: "ORDER BY ts DESC, source_id DESC, byte_offset DESC"}


def _event_row(e: Event) -> Tuple[Any, ...]:
    return (
        e.id, _to_micros(e.timestamp), e.source, e.event_type, e.src_ip, e.username, e.host,
        e.outcome, e.count, None if e.geo is None else _json(e.geo), _json(e.extra), e.raw,
        e.source_id, e.offset,
    )  # fmt: skip


def _row_event(row: Tuple[Any, ...]) -> Event:
    return Event(
        id=row[0],
        timestamp=_from_micros(row[1]),
        source=row[2],
        event_type=row[3],
        src_ip=row[4],
        username=row[5],
        host=row[6],
        outcome=row[7],
        count=row[8],
        geo=None if row[9] is None else json.loads(row[9]),
        extra=json.loads(row[10]),
        raw=row[11],
        source_id=row[12],
        offset=row[13],
    )


def _where(
    src_ip: Optional[str],
    username: Optional[str],
    event_type: Optional[str],
    since: Optional[datetime],
    until: Optional[datetime],
) -> Tuple[str, List[Any]]:
    clauses: List[str] = []
    params: List[Any] = []
    if src_ip is not None:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if username is not None:
        clauses.append("username = ?")
        params.append(username)
    if event_type is not None:
        clauses.append("event_type = ?")
        params.append(event_type)
    if since is not None:
        clauses.append("ts >= ?")  # inclusive
        params.append(_to_micros(since))
    if until is not None:
        clauses.append("ts < ?")  # exclusive, so adjacent windows never overlap
        params.append(_to_micros(until))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


class EventStore(AlertStoreMixin):
    """Events, dead letters and alerts in one SQLite file. Alert methods are in alerts.py."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path)
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")  # deleting an alert removes its evidence and history
        self._init_schema()

    def _init_schema(self) -> None:
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            return
        if version > SCHEMA_VERSION:
            raise StoreError(
                f"database schema is version {version}, newer than this code ({SCHEMA_VERSION}); upgrade Siftlog"
            )
        script = ""
        if version == 0:
            has_events = self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'events'"
            ).fetchone()
            if has_events:
                raise StoreError("database already has an 'events' table but no schema version; refusing to use it")
            script += _SCHEMA
        # Versions 0 and 1 both lack the alert tables. One transaction, so a failed
        # upgrade leaves the database exactly as it was.
        script += ALERT_SCHEMA
        self._conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {SCHEMA_VERSION};\nCOMMIT;")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- writes -----------------------------------------------------------

    def add_events(self, events: Iterable[Event]) -> int:
        """Insert events, skipping ids already present. Returns how many were new."""
        rows = [_event_row(e) for e in events]
        before = self._conn.total_changes
        with self._conn:
            self._conn.executemany(_INSERT_EVENT, rows)
        return self._conn.total_changes - before

    def add_dead_letters(self, letters: Iterable[DeadLetter]) -> int:
        rows = [(d.source_id, d.offset, d.raw, d.reason) for d in letters]
        before = self._conn.total_changes
        with self._conn:
            self._conn.executemany(_INSERT_DEAD, rows)
        return self._conn.total_changes - before

    def backfill_geo(self, resolver: Any) -> Tuple[int, int]:
        """Locate events that have a source address but no location yet.

        Returns (events located, distinct addresses located). Separate from
        ingest on purpose: a GeoIP database often arrives after the logs do, and
        re-ingesting cannot add a location because existing rows are never
        rewritten. Only rows with no location are touched, so it is safe to repeat.
        """
        addresses = [
            row[0]
            for row in self._conn.execute(
                "SELECT DISTINCT src_ip FROM events WHERE geo IS NULL AND src_ip IS NOT NULL"
            )
        ]
        located = found = 0
        with self._conn:
            for address in addresses:
                geo = resolver.lookup(address)
                if geo is None:
                    continue
                cursor = self._conn.execute(
                    "UPDATE events SET geo = ? WHERE src_ip = ? AND geo IS NULL", (_json(geo), address)
                )
                located += cursor.rowcount
                found += 1
        return located, found

    # --- reads ------------------------------------------------------------

    def query(
        self,
        *,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: Optional[int] = None,
        descending: bool = False,
    ) -> List[Event]:
        """Events matching every given filter. ``since`` inclusive, ``until`` exclusive."""
        sql, params = self._select(src_ip, username, event_type, since, until, limit, descending)
        return [_row_event(row) for row in self._conn.execute(sql, params)]

    def iter_events(
        self,
        *,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        batch_size: int = 5000,
    ) -> Iterator[Event]:
        """Like query() but streams in time order without loading everything (replay mode)."""
        sql, params = self._select(src_ip, username, event_type, since, until, None, False)
        cursor = self._conn.execute(sql, params)
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                return
            for row in rows:
                yield _row_event(row)

    def count(
        self,
        *,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        weighted: bool = False,
    ) -> int:
        """Number of matching rows, or with ``weighted`` the sum of their repeat counts.

        One log line can stand for several events ("message repeated 5 times"),
        so rules that threshold on attempts must use ``weighted=True``.
        """
        where, params = _where(src_ip, username, event_type, since, until)
        expr = "COALESCE(SUM(repeat_count), 0)" if weighted else "COUNT(*)"
        return self._conn.execute(f"SELECT {expr} FROM events{where}", params).fetchone()[0]

    def explain_query(
        self,
        *,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[str]:
        """SQLite's plan for query(): lets tests and tuning confirm an index is used."""
        sql, params = self._select(src_ip, username, event_type, since, until, None, False)
        return [row[3] for row in self._conn.execute("EXPLAIN QUERY PLAN " + sql, params)]

    def dead_letters(self, limit: Optional[int] = None) -> List[DeadLetter]:
        sql = "SELECT source_id, byte_offset, raw, reason FROM dead_letters ORDER BY source_id, byte_offset"
        params: List[Any] = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(_check_limit(limit))
        return [DeadLetter(source_id=r[0], offset=r[1], raw=r[2], reason=r[3]) for r in self._conn.execute(sql, params)]

    def dead_letter_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM dead_letters").fetchone()[0]

    def alert_events(self, alert_id: str) -> List[Event]:
        """The evidence behind an alert, in the order the engine recorded it."""
        columns = ", ".join("e." + name.strip() for name in _COLUMNS.split(","))
        return [
            _row_event(row)
            for row in self._conn.execute(
                f"SELECT {columns} FROM alert_events a JOIN events e ON e.id = a.event_id "
                "WHERE a.alert_id = ? ORDER BY a.position",
                (alert_id,),
            )
        ]

    def event_type_counts(self) -> Dict[str, int]:
        return dict(
            self._conn.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY event_type")
        )

    def top_sources(self, limit: int = 10, event_type: str = AUTH_FAILURE) -> List[Tuple[str, int]]:
        """(address, weighted event count) for the busiest sources of one event type."""
        return [
            (row[0], row[1])
            for row in self._conn.execute(
                "SELECT src_ip, SUM(repeat_count) AS n FROM events WHERE event_type = ? AND src_ip IS NOT NULL "
                "GROUP BY src_ip ORDER BY n DESC, src_ip LIMIT ?",
                (event_type, _check_limit(limit)),
            )
        ]

    def time_range(self) -> Tuple[Optional[datetime], Optional[datetime]]:
        first, last = self._conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        return (None, None) if first is None else (_from_micros(first), _from_micros(last))

    # --- internals --------------------------------------------------------

    def _select(
        self,
        src_ip: Optional[str],
        username: Optional[str],
        event_type: Optional[str],
        since: Optional[datetime],
        until: Optional[datetime],
        limit: Optional[int],
        descending: bool,
    ) -> Tuple[str, List[Any]]:
        where, params = _where(src_ip, username, event_type, since, until)
        sql = f"SELECT {_COLUMNS} FROM events{where} {_ORDER[descending]}"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(_check_limit(limit))
        return sql, params

