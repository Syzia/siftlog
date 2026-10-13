"""Replay-mode detection engine: run rules over time-ordered events.

Deterministic by construction: the same events and rules always give the same
alerts, which is what makes rules testable and tunable.

Semantics
---------
**Sliding windows.** For each rule and group, the engine keeps the matching
events from the last ``timespan``, the half-open interval ``(t - timespan, t]``
ending at the newest event. Fixed buckets would miss an attack straddling a
bucket boundary.

**Alerts are episodes.** An alert opens when the rule's condition first holds
for a group, and is extended every time a new event arrives while the condition
still holds. It closes once the condition has not held for ``cooldown``
(default: the rule's ``timespan``); a later burst opens a new alert. So one
attack is one alert, however many events it contains.

The episode follows the *condition*, not merely "matching events keep
arriving". For a rule grouped by host, matching events never stop on an
internet-facing server, so that looser definition would hold the first alert
open forever and suppress every later one.

**Counts are weighted.** One stored event can stand for several log lines
("message repeated 5 times"), so ``event_count`` sums ``Event.count``.
"""
from __future__ import annotations

import hashlib
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

from siftlog.engine.rules import VALUE_COUNT, Rule
from siftlog.events import Event

# Evidence ids kept per alert. Counts stay exact past this; only the id list is capped,
# so an attacker cannot grow one alert without bound.
MAX_EVIDENCE = 1000
_SWEEP_EVERY = 20_000


@dataclass(frozen=True)
class Alert:
    id: str  # deterministic: hash(rule id, group key, first_seen)
    rule_id: str
    title: str
    severity: str
    group_key: str
    first_seen: datetime
    last_seen: datetime  # last time the condition held
    event_count: int  # weighted count of the evidence events
    distinct_count: Optional[int]  # value_count rules: distinct values seen in the episode
    evidence_event_ids: Tuple[str, ...]
    evidence_truncated: bool
    mitre: Tuple[str, ...] = ()


class _Entry(NamedTuple):
    seq: int
    ts: datetime
    weight: int
    value: Optional[str]
    event_id: str


class _Episode:
    __slots__ = ("first_seen", "last_seen", "event_count", "values", "evidence", "truncated", "max_seq")

    def __init__(self, first_seen: datetime) -> None:
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.event_count = 0
        self.values: Set[str] = set()
        self.evidence: List[str] = []
        self.truncated = False
        self.max_seq = 0  # highest window entry already counted into this episode


class _Group:
    __slots__ = ("window", "total", "values", "episode", "seq", "last_ts")

    def __init__(self) -> None:
        self.window: Deque[_Entry] = deque()
        self.total = 0  # weighted number of events in the window
        self.values: Counter = Counter()  # distinct value -> entries in the window
        self.episode: Optional[_Episode] = None
        self.seq = 0
        self.last_ts: Optional[datetime] = None


class ReplayEngine:
    def __init__(self, rules: Sequence[Rule], max_evidence: int = MAX_EVIDENCE) -> None:
        ids = [rule.id for rule in rules]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule ids: {duplicates}")
        self._rules = list(rules)
        self._max_evidence = max_evidence

    def run(self, events: Iterable[Event]) -> List[Alert]:
        """Evaluate every rule over ``events``, which must be in time order."""
        state: List[Dict[str, _Group]] = [{} for _ in self._rules]
        alerts: List[Alert] = []
        last_ts: Optional[datetime] = None
        for n, event in enumerate(events, 1):
            if last_ts is not None and event.timestamp < last_ts:
                raise ValueError(
                    f"events must be in time order: {event.timestamp.isoformat()} after {last_ts.isoformat()}"
                )
            last_ts = event.timestamp
            for rule, groups in zip(self._rules, state):
                if rule.matches(event):
                    self._feed(rule, groups, event, alerts)
            if n % _SWEEP_EVERY == 0:
                self._sweep(state, last_ts, alerts)

        for rule, groups in zip(self._rules, state):
            for key, group in groups.items():
                if group.episode is not None:
                    alerts.append(self._alert(rule, key, group.episode))
        alerts.sort(key=lambda a: (a.first_seen, a.rule_id, a.group_key))
        return alerts

    def _feed(self, rule: Rule, groups: Dict[str, _Group], event: Event, alerts: List[Alert]) -> None:
        key = rule.group_key(event)
        if key is None:
            return
        value: Optional[str] = None
        if rule.type == VALUE_COUNT:
            value = getattr(event, rule.distinct)  # type: ignore[arg-type]
            if value is None:
                return
        group = groups.get(key)
        if group is None:
            group = groups[key] = _Group()

        now = event.timestamp
        cutoff = now - rule.timespan
        window = group.window
        while window and window[0].ts <= cutoff:
            old = window.popleft()
            group.total -= old.weight
            if old.value is not None:
                group.values[old.value] -= 1
                if not group.values[old.value]:
                    del group.values[old.value]

        group.seq += 1
        window.append(_Entry(group.seq, now, event.count, value, event.id))
        group.total += event.count
        if value is not None:
            group.values[value] += 1
        group.last_ts = now

        episode = group.episode
        if episode is not None and now - episode.last_seen > rule.effective_cooldown:
            alerts.append(self._alert(rule, key, episode))
            episode = group.episode = None

        metric = len(group.values) if rule.type == VALUE_COUNT else group.total
        if not rule.holds(metric):
            return

        if episode is None:
            episode = group.episode = _Episode(first_seen=window[0].ts)
        # Entries not yet counted are always a suffix of the window: the events that
        # triggered a new alert, or those that arrived during a brief dip.
        pending: List[_Entry] = []
        for entry in reversed(window):
            if entry.seq <= episode.max_seq:
                break
            pending.append(entry)
        for entry in reversed(pending):
            episode.event_count += entry.weight
            if entry.value is not None:
                episode.values.add(entry.value)
            if len(episode.evidence) < self._max_evidence:
                episode.evidence.append(entry.event_id)
            else:
                episode.truncated = True
        episode.max_seq = group.seq
        episode.last_seen = now

    def _sweep(self, state: List[Dict[str, _Group]], now: datetime, alerts: List[Alert]) -> None:
        """Drop groups that have gone quiet, so memory tracks active groups, not all ever seen.

        Equivalent to what the next event for that group would do anyway: by then
        its window would be empty and its episode past the cooldown.
        """
        for rule, groups in zip(self._rules, state):
            idle = max(rule.timespan, rule.effective_cooldown)
            for key in [k for k, g in groups.items() if g.last_ts is not None and now - g.last_ts > idle]:
                group = groups.pop(key)
                if group.episode is not None:
                    alerts.append(self._alert(rule, key, group.episode))

    @staticmethod
    def _alert(rule: Rule, key: str, episode: _Episode) -> Alert:
        digest = hashlib.sha256(f"{rule.id}\x00{key}\x00{episode.first_seen.isoformat()}".encode("utf-8"))
        return Alert(
            id=digest.hexdigest()[:32],
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            group_key=key,
            first_seen=episode.first_seen,
            last_seen=episode.last_seen,
            event_count=episode.event_count,
            distinct_count=len(episode.values) if rule.type == VALUE_COUNT else None,
            evidence_event_ids=tuple(episode.evidence),
            evidence_truncated=episode.truncated,
            mitre=rule.mitre,
        )


def run_rules(rules: Sequence[Rule], events: Iterable[Event]) -> List[Alert]:
    """Convenience wrapper: evaluate ``rules`` over time-ordered ``events``."""
    return ReplayEngine(rules).run(events)
