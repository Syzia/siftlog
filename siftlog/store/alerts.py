"""Alert persistence: what the rules detected, and what an analyst decided about it.

The two are kept apart on purpose.

**Detections are recomputed.** Replay is deterministic and alert ids are a hash
of (rule, group, first_seen), so re-running the engine reproduces the same
alerts. ``sync_alerts`` makes the table match the latest replay.

**Decisions persist.** A sync never touches ``status`` or ``note``, with one
exception: an alert that was *closed* and has since gained activity is reopened.
Closing means "handled", not "muted", so an attack that carries on must not
stay hidden behind a closed alert.

**Nothing an analyst touched is silently deleted.** If a rule change means the
latest replay no longer produces an alert, it is removed only if it was never
acted on. Otherwise it is kept and marked ``superseded``.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from siftlog.engine.replay import Alert
from siftlog.store._common import check_limit, from_micros, to_json, to_micros

STATUSES = ("open", "ack", "closed")
SYSTEM_ACTOR = "siftlog"

ALERT_SCHEMA = """
CREATE TABLE alerts (
    id                 TEXT    PRIMARY KEY,
    rule_id            TEXT    NOT NULL,
    title              TEXT    NOT NULL,
    severity           TEXT    NOT NULL,
    group_key          TEXT    NOT NULL,
    first_seen         INTEGER NOT NULL,
    last_seen          INTEGER NOT NULL,
    event_count        INTEGER NOT NULL,
    distinct_count     INTEGER,
    evidence_truncated INTEGER NOT NULL,
    mitre              TEXT    NOT NULL,
    summary            TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ack', 'closed')),
    status_changed_at  INTEGER,
    note               TEXT    NOT NULL DEFAULT '',
    superseded         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_alerts_last_seen ON alerts (last_seen);
CREATE INDEX idx_alerts_rule ON alerts (rule_id);

-- Evidence: one row per event, in the order the engine recorded them.
CREATE TABLE alert_events (
    alert_id TEXT    NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    event_id TEXT    NOT NULL,
    PRIMARY KEY (alert_id, position)
);
CREATE INDEX idx_alert_events_event ON alert_events (event_id);

-- Who changed an alert's status, when, and why. Includes changes made by Siftlog itself.
CREATE TABLE alert_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   TEXT    NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    changed_at INTEGER NOT NULL,
    old_status TEXT    NOT NULL,
    new_status TEXT    NOT NULL,
    actor      TEXT    NOT NULL,
    note       TEXT    NOT NULL
);
CREATE INDEX idx_alert_history_alert ON alert_history (alert_id, id);
"""

_COLUMNS = (
    "id, rule_id, title, severity, group_key, first_seen, last_seen, event_count, distinct_count, "
    "evidence_truncated, mitre, summary, status, status_changed_at, note, superseded"
)
_BREAKDOWNS = {"status", "severity", "rule_id"}  # the only columns stats may group by
# What a stored alert is compared against to tell "updated" from "unchanged".
_ROW = (
    "SELECT id, status, superseded, title, severity, last_seen, event_count, distinct_count, "
    "evidence_truncated, mitre, summary FROM alerts"
)


@dataclass(frozen=True)
class StoredAlert:
    alert: Alert  # evidence ids are filled by get_alert(), and left empty in listings
    status: str
    status_changed_at: Optional[datetime]
    note: str
    superseded: bool  # the latest replay no longer produces this alert


@dataclass(frozen=True)
class HistoryEntry:
    changed_at: datetime
    old_status: str
    new_status: str
    actor: str
    note: str


@dataclass(frozen=True)
class SyncReport:
    new: int = 0
    updated: int = 0
    unchanged: int = 0
    reopened: int = 0  # closed alerts whose attack carried on
    removed: int = 0  # no longer produced, never acted on
    superseded: int = 0  # no longer produced, but an analyst had acted on them


def _stored(row: Tuple[Any, ...], evidence: Tuple[str, ...] = ()) -> StoredAlert:
    return StoredAlert(
        alert=Alert(
            id=row[0],
            rule_id=row[1],
            title=row[2],
            severity=row[3],
            group_key=row[4],
            first_seen=from_micros(row[5]),
            last_seen=from_micros(row[6]),
            event_count=row[7],
            distinct_count=row[8],
            evidence_event_ids=evidence,
            evidence_truncated=bool(row[9]),
            mitre=tuple(json.loads(row[10])),
            summary=row[11],
        ),
        status=row[12],
        status_changed_at=None if row[13] is None else from_micros(row[13]),
        note=row[14],
        superseded=bool(row[15]),
    )


def _detection(alert: Alert) -> Tuple[Any, ...]:
    """The fields a replay decides. Compared to tell 'updated' from 'unchanged'."""
    return (
        alert.title, alert.severity, to_micros(alert.last_seen), alert.event_count, alert.distinct_count,
        int(alert.evidence_truncated), to_json(list(alert.mitre)), alert.summary,
    )  # fmt: skip


class AlertStoreMixin:
    _conn: sqlite3.Connection

    # --- writes -----------------------------------------------------------

    def sync_alerts(
        self, alerts: Iterable[Alert], rule_ids: Iterable[str], now: Optional[datetime] = None
    ) -> SyncReport:
        """Make the alerts table match a full replay of ``rule_ids``.

        ``alerts`` must be everything those rules produce over the whole event
        store: alerts of those rules that are absent are treated as no longer
        produced. Alerts belonging to other rules are left alone.
        """
        alerts = list(alerts)
        rule_ids = sorted(set(rule_ids))
        stray = sorted({a.rule_id for a in alerts} - set(rule_ids))
        if stray:
            raise ValueError(f"alerts from rules that were not declared as run: {stray}")
        now_us = to_micros(now or datetime.now(timezone.utc))
        counts = dict.fromkeys(("new", "updated", "unchanged", "reopened", "removed", "superseded"), 0)
        if not rule_ids:
            return SyncReport()

        with self._conn:
            marks = ",".join("?" * len(rule_ids))  # placeholders only; values are bound
            existing: Dict[str, Tuple[Any, ...]] = {
                row[0]: row for row in self._conn.execute(f"{_ROW} WHERE rule_id IN ({marks})", rule_ids)
            }
            seen = set()
            for alert in alerts:
                seen.add(alert.id)
                self._upsert(alert, existing.get(alert.id), counts, now_us)

            for alert_id, row in existing.items():
                if alert_id in seen:
                    continue
                acted_on = row[1] != "open" or self._conn.execute(
                    "SELECT 1 FROM alert_history WHERE alert_id = ? LIMIT 1", (alert_id,)
                ).fetchone()
                if not acted_on:
                    self._conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
                    counts["removed"] += 1
                elif not row[2]:
                    self._conn.execute("UPDATE alerts SET superseded = 1 WHERE id = ?", (alert_id,))
                    counts["superseded"] += 1
        return SyncReport(**counts)

    def upsert_alerts(self, alerts: Iterable[Alert], now: Optional[datetime] = None) -> SyncReport:
        """Store new alerts and update ones that changed, removing nothing.

        This is what streaming uses: it sees alerts a few at a time, so the
        absence of an alert from one batch says nothing about whether it still
        exists. The same rules apply as for a full sync: decisions are kept, and
        a closed alert that gained activity is reopened.
        """
        now_us = to_micros(now or datetime.now(timezone.utc))
        counts = dict.fromkeys(("new", "updated", "unchanged", "reopened", "removed", "superseded"), 0)
        with self._conn:
            for alert in alerts:
                row = self._conn.execute(f"{_ROW} WHERE id = ?", (alert.id,)).fetchone()
                self._upsert(alert, row, counts, now_us)
        return SyncReport(**counts)

    def _upsert(self, alert: Alert, row: Optional[Tuple[Any, ...]], counts: Dict[str, int], now_us: int) -> None:
        detection = _detection(alert)
        if row is None:
            self._conn.execute(
                "INSERT INTO alerts (id, rule_id, group_key, first_seen, title, severity, last_seen, "
                "event_count, distinct_count, evidence_truncated, mitre, summary) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (alert.id, alert.rule_id, alert.group_key, to_micros(alert.first_seen)) + detection,
            )
            self._write_evidence(alert)
            counts["new"] += 1
            return

        status, was_superseded, old_last_seen = row[1], row[2], row[5]
        if tuple(row[3:]) == detection:
            counts["unchanged"] += 1
        else:
            self._conn.execute(
                "UPDATE alerts SET title = ?, severity = ?, last_seen = ?, event_count = ?, "
                "distinct_count = ?, evidence_truncated = ?, mitre = ?, summary = ? WHERE id = ?",
                detection + (alert.id,),
            )
            self._conn.execute("DELETE FROM alert_events WHERE alert_id = ?", (alert.id,))
            self._write_evidence(alert)
            counts["updated"] += 1
            if status == "closed" and detection[2] > old_last_seen:
                self._change_status(
                    alert.id, "closed", "open", SYSTEM_ACTOR, now_us,
                    "reopened: activity continued after the alert was closed",
                )  # fmt: skip
                counts["reopened"] += 1
        if was_superseded:
            self._conn.execute("UPDATE alerts SET superseded = 0 WHERE id = ?", (alert.id,))

    def set_alert_status(
        self,
        alert_id: str,
        status: str,
        note: str = "",
        actor: str = "analyst",
        now: Optional[datetime] = None,
    ) -> StoredAlert:
        """Record an analyst's decision. Raises KeyError for an unknown alert."""
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        now_us = to_micros(now or datetime.now(timezone.utc))
        with self._conn:
            row = self._conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if row is None:
                raise KeyError(alert_id)
            if row[0] != status or note:
                self._change_status(alert_id, row[0], status, actor, now_us, note)
        stored = self.get_alert(alert_id)
        assert stored is not None
        return stored

    def _change_status(self, alert_id: str, old: str, new: str, actor: str, now_us: int, note: str) -> None:
        self._conn.execute(
            "UPDATE alerts SET status = ?, status_changed_at = ?, note = ? WHERE id = ?",
            (new, now_us, note, alert_id),
        )
        self._conn.execute(
            "INSERT INTO alert_history (alert_id, changed_at, old_status, new_status, actor, note) "
            "VALUES (?,?,?,?,?,?)",
            (alert_id, now_us, old, new, actor, note),
        )

    def _write_evidence(self, alert: Alert) -> None:
        self._conn.executemany(
            "INSERT INTO alert_events (alert_id, position, event_id) VALUES (?,?,?)",
            [(alert.id, position, event_id) for position, event_id in enumerate(alert.evidence_event_ids)],
        )

    # --- reads ------------------------------------------------------------

    def get_alert(self, alert_id: str) -> Optional[StoredAlert]:
        row = self._conn.execute(f"SELECT {_COLUMNS} FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            return None
        evidence = tuple(
            r[0]
            for r in self._conn.execute(
                "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY position", (alert_id,)
            )
        )
        return _stored(row, evidence)

    def list_alerts(self, *, limit: int = 100, offset: int = 0, **filters: Any) -> List[StoredAlert]:
        """Newest activity first. Filters: status, severity, rule_id, group_key, since, until,
        include_superseded. ``since``/``until`` select alerts active in that range."""
        where, params = _where(**filters)
        sql = f"SELECT {_COLUMNS} FROM alerts{where} ORDER BY last_seen DESC, id LIMIT ? OFFSET ?"
        return [_stored(row) for row in self._conn.execute(sql, params + [check_limit(limit), check_limit(offset)])]

    def count_alerts(self, **filters: Any) -> int:
        where, params = _where(**filters)
        return self._conn.execute(f"SELECT COUNT(*) FROM alerts{where}", params).fetchone()[0]

    def alert_history(self, alert_id: str) -> List[HistoryEntry]:
        return [
            HistoryEntry(from_micros(r[0]), r[1], r[2], r[3], r[4])
            for r in self._conn.execute(
                "SELECT changed_at, old_status, new_status, actor, note FROM alert_history "
                "WHERE alert_id = ? ORDER BY id",
                (alert_id,),
            )
        ]

    def alert_breakdown(self, column: str) -> Dict[str, int]:
        """Current (not superseded) alerts counted by status, severity or rule_id."""
        if column not in _BREAKDOWNS:  # never interpolate a caller-supplied column name
            raise ValueError(f"cannot break alerts down by {column!r}")
        return dict(
            self._conn.execute(
                f"SELECT {column}, COUNT(*) FROM alerts WHERE superseded = 0 GROUP BY {column} ORDER BY {column}"
            ).fetchall()
        )

    def alerts_per_day(self) -> List[Tuple[str, int]]:
        """(UTC date, alerts that started that day), oldest first."""
        day = 86_400_000_000
        return [
            (from_micros(bucket * day).date().isoformat(), count)
            for bucket, count in self._conn.execute(
                "SELECT first_seen / ? AS bucket, COUNT(*) FROM alerts WHERE superseded = 0 "
                "GROUP BY bucket ORDER BY bucket",
                (day,),
            )
        ]


def _where(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    group_key: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    include_superseded: bool = False,
) -> Tuple[str, List[Any]]:
    clauses: List[str] = []
    params: List[Any] = []
    for column, value in (("status", status), ("severity", severity), ("rule_id", rule_id), ("group_key", group_key)):
        if value is not None:
            clauses.append(f"{column} = ?")  # column names are the fixed strings above
            params.append(value)
    if since is not None:
        clauses.append("last_seen >= ?")
        params.append(to_micros(since))
    if until is not None:
        clauses.append("first_seen < ?")
        params.append(to_micros(until))
    if not include_superseded:
        clauses.append("superseded = 0")
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params
