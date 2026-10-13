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
("message repeated 5 times"), so counts sum ``Event.count``.

Each rule type has its own evaluator:

* ``event_count`` / ``value_count``: a threshold on the window.
* ``temporal_ordered``: the steps must be satisfied in order inside the window.
  The check runs only when an event matching the *final* step arrives. That is
  a definition as well as a saving: only an event that completes the sequence
  opens or extends an alert, so a stray failure after the successful login is
  not evidence. It also keeps a 10,000-failure brute force from rescanning its
  window on every failure.
* ``impossible_travel``: each located event is compared with the previous
  located event for the same group.
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque, Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

from siftlog.enrich.geo import haversine_km
from siftlog.engine.rules import IMPOSSIBLE_TRAVEL, TEMPORAL_ORDERED, VALUE_COUNT, Rule
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
    summary: str = ""  # human-readable detail, such as the distance and speed of impossible travel


class _Episode:
    __slots__ = ("first_seen", "last_seen", "event_count", "values", "evidence", "truncated", "max_seq", "summary")

    def __init__(self, first_seen: datetime) -> None:
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.event_count = 0
        self.values: Set[str] = set()
        self.evidence: List[str] = []
        self.truncated = False
        self.max_seq = 0  # highest window entry already counted into this episode
        self.summary = ""

    def add(self, event_id: str, weight: int, limit: int) -> None:
        self.event_count += weight
        if len(self.evidence) < limit:
            self.evidence.append(event_id)
        else:
            self.truncated = True


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
        summary=episode.summary,
    )


class _Evaluator:
    """Per-rule state. Subclasses keep one small record per active group."""

    def __init__(self, rule: Rule, max_evidence: int) -> None:
        self.rule = rule
        self.max_evidence = max_evidence
        self.groups: Dict[str, Any] = {}

    def feed(self, event: Event, alerts: List[Alert]) -> None:
        raise NotImplementedError

    def _expire(self, key: str, group: Any, now: datetime, alerts: List[Alert]) -> Optional[_Episode]:
        """Close the group's episode if its condition has not held for the cooldown."""
        episode = group.episode
        if episode is not None and now - episode.last_seen > self.rule.effective_cooldown:
            alerts.append(_alert(self.rule, key, episode))
            episode = group.episode = None
        return episode

    def sweep(self, now: datetime, alerts: List[Alert]) -> None:
        """Drop groups that have gone quiet, so memory tracks active groups, not all ever seen.

        Equivalent to what the next event for that group would do anyway: by then
        its window would be empty and its episode past the cooldown.
        """
        idle = max(self.rule.timespan, self.rule.effective_cooldown)
        for key in [k for k, g in self.groups.items() if now - g.last_ts > idle]:
            group = self.groups.pop(key)
            if group.episode is not None:
                alerts.append(_alert(self.rule, key, group.episode))

    def finish(self, alerts: List[Alert]) -> None:
        for key, group in self.groups.items():
            if group.episode is not None:
                alerts.append(_alert(self.rule, key, group.episode))


# --- event_count / value_count ------------------------------------------------


class _Entry(NamedTuple):
    seq: int
    ts: datetime
    weight: int
    value: Optional[str]
    event_id: str


class _CountGroup:
    __slots__ = ("window", "total", "values", "episode", "seq", "last_ts")

    def __init__(self, now: datetime) -> None:
        self.window: Deque[_Entry] = deque()
        self.total = 0  # weighted number of events in the window
        self.values: Counter = Counter()  # distinct value -> entries in the window
        self.episode: Optional[_Episode] = None
        self.seq = 0
        self.last_ts = now


class _CountEvaluator(_Evaluator):
    def feed(self, event: Event, alerts: List[Alert]) -> None:
        rule = self.rule
        key = rule.group_key(event)
        if key is None:
            return
        value: Optional[str] = None
        if rule.type == VALUE_COUNT:
            value = getattr(event, rule.distinct)  # type: ignore[arg-type]
            if value is None:
                return
        now = event.timestamp
        group = self.groups.get(key)
        if group is None:
            group = self.groups[key] = _CountGroup(now)

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

        episode = self._expire(key, group, now, alerts)
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
            episode.add(entry.event_id, entry.weight, self.max_evidence)
            if entry.value is not None:
                episode.values.add(entry.value)
        episode.max_seq = group.seq
        episode.last_seen = now


# --- temporal_ordered ---------------------------------------------------------


class _SeqEntry(NamedTuple):
    seq: int
    ts: datetime
    weight: int
    steps: Tuple[int, ...]  # indexes of the steps this event matches
    event_id: str


class _SeqGroup:
    __slots__ = ("window", "episode", "seq", "last_ts")

    def __init__(self, now: datetime) -> None:
        self.window: Deque[_SeqEntry] = deque()
        self.episode: Optional[_Episode] = None
        self.seq = 0
        self.last_ts = now


class _SequenceEvaluator(_Evaluator):
    def feed(self, event: Event, alerts: List[Alert]) -> None:
        rule = self.rule
        matched = tuple(i for i, step in enumerate(rule.steps) if step.matches(event))
        if not matched:
            return
        key = rule.group_key(event)
        if key is None:
            return
        now = event.timestamp
        group = self.groups.get(key)
        if group is None:
            group = self.groups[key] = _SeqGroup(now)

        cutoff = now - rule.timespan
        window = group.window
        while window and window[0].ts <= cutoff:
            window.popleft()
        group.seq += 1
        window.append(_SeqEntry(group.seq, now, event.count, matched, event.id))
        group.last_ts = now

        episode = self._expire(key, group, now, alerts)
        # Only an event matching the final step can complete the sequence, and only a
        # completing event opens or extends an alert.
        if len(rule.steps) - 1 not in matched or not self._complete(window):
            return

        if episode is None:
            episode = group.episode = _Episode(first_seen=window[0].ts)
        pending: List[_SeqEntry] = []
        for entry in reversed(window):
            if entry.seq <= episode.max_seq:
                break
            pending.append(entry)
        for entry in reversed(pending):
            episode.add(entry.event_id, entry.weight, self.max_evidence)
        episode.max_seq = group.seq
        episode.last_seen = now

    def _complete(self, window: Iterable[_SeqEntry]) -> bool:
        """Are all steps satisfied, in order, by the events in the window?

        Greedy: finish each step as early as possible, which leaves the most room
        for the steps after it. An event counts towards one step only.
        """
        steps = self.rule.steps
        stage, count = 0, 0
        for entry in window:
            if stage in entry.steps:
                count += entry.weight
                if count >= steps[stage].threshold:
                    stage, count = stage + 1, 0
                    if stage == len(steps):
                        return True
        return False


# --- impossible_travel --------------------------------------------------------


class _Located(NamedTuple):
    ts: datetime
    lat: float
    lon: float
    event_id: str
    place: str


class _TravelGroup:
    __slots__ = ("last", "episode", "last_ts", "last_evidence")

    def __init__(self, now: datetime) -> None:
        self.last: Optional[_Located] = None
        self.episode: Optional[_Episode] = None
        self.last_ts = now
        self.last_evidence: Optional[str] = None  # newest event id already in the episode


def _coordinates(geo: Any) -> Optional[Tuple[float, float, str]]:
    if not isinstance(geo, dict):
        return None
    lat, lon = geo.get("lat"), geo.get("lon")
    for number in (lat, lon):
        if isinstance(number, bool) or not isinstance(number, (int, float)) or math.isnan(number):
            return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    place = geo.get("city") or geo.get("country") or f"{lat:.2f},{lon:.2f}"
    return float(lat), float(lon), str(place)


class _TravelEvaluator(_Evaluator):
    def feed(self, event: Event, alerts: List[Alert]) -> None:
        rule = self.rule
        located = _coordinates(event.geo)
        if located is None:
            return  # an address we cannot place says nothing about travel
        key = rule.group_key(event)
        if key is None:
            return
        now = event.timestamp
        group = self.groups.get(key)
        if group is None:
            group = self.groups[key] = _TravelGroup(now)
        episode = self._expire(key, group, now, alerts)
        if episode is None:
            group.last_evidence = None

        previous = group.last
        current = _Located(now, located[0], located[1], event.id, located[2])
        group.last = current
        group.last_ts = now
        if previous is None or now - previous.ts > rule.timespan:
            return

        distance = haversine_km(previous.lat, previous.lon, current.lat, current.lon)
        if distance <= 0 or distance < rule.min_distance_km:
            return
        hours = (now - previous.ts).total_seconds() / 3600
        speed = math.inf if hours <= 0 else distance / hours
        if speed <= rule.max_speed_kmh:  # type: ignore[operator]
            return

        if episode is None:
            episode = group.episode = _Episode(first_seen=previous.ts)
            pace = "at the same moment" if hours <= 0 else f"in {hours * 60:,.0f} min ({speed:,.0f} km/h)"
            episode.summary = f"{previous.place} -> {current.place}: {distance:,.0f} km {pace}"
        if group.last_evidence != previous.event_id:
            episode.add(previous.event_id, 1, self.max_evidence)
        episode.add(current.event_id, 1, self.max_evidence)
        group.last_evidence = current.event_id
        episode.last_seen = now


def _evaluator(rule: Rule, max_evidence: int) -> _Evaluator:
    if rule.type == TEMPORAL_ORDERED:
        return _SequenceEvaluator(rule, max_evidence)
    if rule.type == IMPOSSIBLE_TRAVEL:
        return _TravelEvaluator(rule, max_evidence)
    return _CountEvaluator(rule, max_evidence)


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
        evaluators = [_evaluator(rule, self._max_evidence) for rule in self._rules]
        alerts: List[Alert] = []
        last_ts: Optional[datetime] = None
        for n, event in enumerate(events, 1):
            if last_ts is not None and event.timestamp < last_ts:
                raise ValueError(
                    f"events must be in time order: {event.timestamp.isoformat()} after {last_ts.isoformat()}"
                )
            last_ts = event.timestamp
            for evaluator in evaluators:
                if evaluator.rule.matches(event):
                    evaluator.feed(event, alerts)
            if n % _SWEEP_EVERY == 0:
                for evaluator in evaluators:
                    evaluator.sweep(last_ts, alerts)

        for evaluator in evaluators:
            evaluator.finish(alerts)
        alerts.sort(key=lambda a: (a.first_seen, a.rule_id, a.group_key))
        return alerts


def run_rules(rules: Sequence[Rule], events: Iterable[Event]) -> List[Alert]:
    """Convenience wrapper: evaluate ``rules`` over time-ordered ``events``."""
    return ReplayEngine(rules).run(events)
