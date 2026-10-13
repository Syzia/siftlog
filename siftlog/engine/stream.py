"""Streaming detection: the same evaluators as replay, fed a little at a time.

Replay answers "what would the rules have said about this stored history?".
Streaming answers "what do they say now?", and has three problems replay does not.

**An alert must be visible while the attack is still running.** Replay reports
an alert when its episode ends. ``feed`` instead returns every alert that
opened, grew or closed because of the events it was given. An alert's id is
fixed when its episode opens, so later versions update the same stored alert.

**Events can arrive slightly out of order.** ``ReorderBuffer`` holds each event
for a short time after it arrives and releases events in timestamp order.
Anything arriving later than that is still stored, but is skipped by detection
and counted in ``late_events``. It is picked up again the next time the engine
is rebuilt from the store.

**State must stay bounded.** Group keys are attacker-controlled, so each rule
tracks a capped number of groups and forgets the least recently active first.

Because the evaluators are shared, feeding events in order in any number of
pieces ends in exactly the alerts a replay of the same events produces.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from siftlog.engine.replay import (
    DEFAULT_MAX_GROUPS,
    MAX_EVIDENCE,
    Alert,
    _check_unique,
    _evaluator,
)
from siftlog.engine.rules import Rule
from siftlog.events import Event

# How much event time passes between sweeps for groups that have gone quiet.
_SWEEP_INTERVAL = timedelta(seconds=60)


def _order(event: Event) -> Tuple[datetime, str, int]:
    return (event.timestamp, event.source_id, event.offset)


def _latest(alerts: Iterable[Alert]) -> List[Alert]:
    """One entry per alert id, keeping the most recent version, in a stable order."""
    by_id = {alert.id: alert for alert in alerts}
    return sorted(by_id.values(), key=lambda a: (a.first_seen, a.rule_id, a.group_key))


class StreamingEngine:
    def __init__(
        self, rules: Sequence[Rule], max_evidence: int = MAX_EVIDENCE, max_groups: int = DEFAULT_MAX_GROUPS
    ) -> None:
        _check_unique(rules)
        self._evaluators = [_evaluator(rule, max_evidence, max_groups) for rule in rules]
        self._last_ts: Optional[datetime] = None
        self._last_sweep: Optional[datetime] = None
        self.late_events = 0  # skipped because something later had already been processed

    def feed(self, events: Iterable[Event]) -> List[Alert]:
        """Process ``events`` and return the alerts that opened, grew or closed as a result."""
        closed: List[Alert] = []
        for event in sorted(events, key=_order):
            if self._last_ts is not None and event.timestamp < self._last_ts:
                self.late_events += 1
                continue
            self._last_ts = event.timestamp
            for evaluator in self._evaluators:
                if evaluator.rule.matches(event):
                    evaluator.feed(event, closed)
        if self._last_ts is not None and (
            self._last_sweep is None or self._last_ts - self._last_sweep >= _SWEEP_INTERVAL
        ):
            for evaluator in self._evaluators:
                evaluator.sweep(self._last_ts, closed)
            self._last_sweep = self._last_ts
        return _latest(closed + [snap for evaluator in self._evaluators for snap in evaluator.collect()])

    def open_alerts(self) -> List[Alert]:
        """Every alert whose episode is still open, as it stands now."""
        current: List[Alert] = []
        for evaluator in self._evaluators:
            evaluator.finish(current)  # reads state; does not close anything
        return _latest(current)

    @property
    def evicted_groups(self) -> int:
        return sum(evaluator.evicted for evaluator in self._evaluators)

    @property
    def tracked_groups(self) -> int:
        return sum(len(evaluator.groups) for evaluator in self._evaluators)


class ReorderBuffer:
    """Hold events briefly after they arrive, then release them in timestamp order.

    ``lateness`` is how long to wait for stragglers, in seconds of wall-clock
    time since an event arrived. Zero disables the wait.
    """

    def __init__(self, lateness: float, clock: Callable[[], float] = time.monotonic) -> None:
        if lateness < 0:
            raise ValueError("lateness cannot be negative")
        self._lateness = lateness
        self._clock = clock
        self._held: List[Tuple[float, Event]] = []

    def add(self, events: Iterable[Event]) -> None:
        now = self._clock()
        self._held.extend((now, event) for event in events)

    def release(self) -> List[Event]:
        """Events that have waited long enough, oldest timestamp first."""
        cutoff = self._clock() - self._lateness
        ready = [event for arrived, event in self._held if arrived <= cutoff]
        self._held = [(arrived, event) for arrived, event in self._held if arrived > cutoff]
        return sorted(ready, key=_order)

    def drain(self) -> List[Event]:
        """Everything still held, regardless of how long it has waited."""
        ready = sorted((event for _, event in self._held), key=_order)
        self._held = []
        return ready

    def __len__(self) -> int:
        return len(self._held)
