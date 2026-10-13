"""Live detection: follow log files and raise alerts as events arrive.

    python -m siftlog.watch /var/log/auth.log --db siftlog.db --rules rules --year 2026

One process does the whole pipeline continuously: read new lines, parse, add
locations, store, feed the rules, and store any alert that opened or changed.
The API reads the same database, so alerts appear there within seconds.

**Starting up rebuilds from the store.** ``start`` first ingests whatever the
files already hold, then feeds the *entire* event store through the rules and
reconciles the alert table, exactly as a full replay would. That makes a restart
safe mid-attack (the same alert continues, with the same id and any analyst
decision intact) and repairs anything missed while the process was down. The
cost is one pass over all stored events at startup.

**After that it is incremental.** Each ``step`` only handles new lines. Events
are held for ``lateness`` seconds so slight disorder can be put right; anything
later than that is stored but skipped by detection until the next restart.
"""
from __future__ import annotations

import argparse
import signal
import time
from dataclasses import dataclass, field
from datetime import timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from siftlog.engine import Alert, Rule, RuleError, load_rules
from siftlog.engine.replay import DEFAULT_MAX_GROUPS
from siftlog.engine.stream import ReorderBuffer, StreamingEngine
from siftlog.enrich import GeoResolver, enrich
from siftlog.events import DeadLetter, Event
from siftlog.ingest.tail import TailReader
from siftlog.parsers import PARSERS
from siftlog.store import EventStore, SyncReport


@dataclass
class StepReport:
    lines: int = 0
    events: int = 0
    dead_letters: int = 0
    late_events: int = 0  # stored, but too late to be put in order for detection
    opened: List[Alert] = field(default_factory=list)
    updated: List[Alert] = field(default_factory=list)


class Watcher:
    def __init__(
        self,
        paths: Sequence[str],
        store: EventStore,
        rules: Sequence[Rule],
        make_parser: Callable[[], Any],
        *,
        lateness: float = 2.0,
        resolver: Optional[GeoResolver] = None,
        clock: Callable[[], float] = time.monotonic,
        max_groups: int = DEFAULT_MAX_GROUPS,
    ) -> None:
        self._store = store
        self._rules = list(rules)
        self._make_parser = make_parser
        self._resolver = resolver
        self.engine = StreamingEngine(rules, max_groups=max_groups)
        self._buffer = ReorderBuffer(lateness, clock)
        self._parsers: Dict[str, Any] = {}  # stream identity -> parser
        self._carry: Dict[str, Any] = {}  # path -> parser state, handed to the next file after a rotation
        self._readers = [TailReader(p, resume=lambda sid, path=p: self._resume(path, sid)) for p in paths]
        self._versions: Dict[str, Alert] = {}  # alert id -> what was last stored
        self._started = False

    def _resume(self, path: str, source_id: str) -> Optional[Tuple[int, bool]]:
        """A reader has identified a file: give it a parser, and tell it where to carry on from."""
        parser = self._make_parser()
        self._parsers[source_id] = parser
        saved = self._store.get_checkpoint(source_id)
        if saved is not None:
            offset, state = saved
            parser.restore(state["parser"])
            return offset, bool(state.get("skipping"))
        if path in self._carry:
            # A new file at a path already being followed: it continues the old one's year.
            parser.restore(self._carry[path])
        return None

    def _ingest(self) -> Tuple[List[Event], int, int]:
        fresh: List[Event] = []
        lines = dead = 0
        for reader in self._readers:
            batch = reader.poll()
            if not batch:
                continue
            events: List[Event] = []
            letters: List[DeadLetter] = []
            for source_id, offset, text in batch:
                result = self._parsers[source_id].parse_line(text, source_id, offset)
                events.extend(result.events)
                if result.dead_letter is not None:
                    letters.append(result.dead_letter)
            if self._resolver is not None:
                events = [enrich(event, self._resolver) for event in events]
            self._store.add_events(events)
            self._store.add_dead_letters(letters)
            if reader.source_id is not None:
                state = self._parsers[reader.source_id].state()
                self._carry[reader.path] = state
                # Saved after the events, so a crash in between only means re-reading
                # lines whose events are already stored, which is a no-op.
                self._store.save_checkpoint(
                    reader.source_id, reader.path, reader.offset, {"parser": state, "skipping": reader.skipping}
                )
            fresh.extend(events)
            lines += len(batch)
            dead += len(letters)
        return fresh, lines, dead

    def start(self) -> SyncReport:
        """Catch up on the files, then rebuild all detection state from the store."""
        self._ingest()
        alerts = self.engine.feed(self._store.iter_events())
        self._versions = {alert.id: alert for alert in alerts}
        self._started = True
        return self._store.sync_alerts(alerts, [rule.id for rule in self._rules])

    def step(self) -> StepReport:
        """Handle whatever is new since the last call."""
        if not self._started:
            raise RuntimeError("call start() before step()")
        fresh, lines, dead = self._ingest()
        self._buffer.add(fresh)
        return self._detect(self._buffer.release(), StepReport(lines=lines, events=len(fresh), dead_letters=dead))

    def close(self) -> StepReport:
        """Process anything still waiting in the reorder buffer and release the files."""
        report = self._detect(self._buffer.drain(), StepReport()) if self._started else StepReport()
        for reader in self._readers:
            reader.close()
        return report

    def _detect(self, events: List[Event], report: StepReport) -> StepReport:
        late_before = self.engine.late_events
        changed = [a for a in self.engine.feed(events) if self._versions.get(a.id) != a]
        if changed:
            self._store.upsert_alerts(changed)
        for alert in changed:
            (report.updated if alert.id in self._versions else report.opened).append(alert)
            self._versions[alert.id] = alert
        report.late_events = self.engine.late_events - late_before
        return report


def _describe(alert: Alert) -> str:
    distinct = "" if alert.distinct_count is None else f", {alert.distinct_count} distinct"
    summary = f"  {alert.summary}" if alert.summary else ""
    return (
        f"[{alert.severity}] {alert.rule_id} {alert.group_key} "
        f"since {alert.first_seen:%Y-%m-%d %H:%M:%S}: {alert.event_count} events{distinct}{summary}"
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m siftlog.watch",
        description="Follow log files and raise alerts as events arrive. Stop with Ctrl+C.",
    )
    parser.add_argument("files", nargs="+", help="log files to follow")
    parser.add_argument("--db", default="siftlog.db")
    parser.add_argument("--rules", default="rules", help="rule file or directory")
    parser.add_argument("--source", choices=sorted(PARSERS), default="sshd")
    parser.add_argument("--year", type=int, required=True,
                        help="year of each file's first line (syslog timestamps have none); "
                             "a file already being followed resumes with the year it had reached")
    parser.add_argument("--tz", default="UTC", help="timezone the host logged in, e.g. Europe/London")
    parser.add_argument("--poll", type=float, default=1.0, help="seconds between checks for new lines")
    parser.add_argument("--lateness", type=float, default=2.0,
                        help="seconds to hold events so slightly out-of-order ones can be put right")
    geo = parser.add_mutually_exclusive_group()
    geo.add_argument("--geoip", metavar="FILE.mmdb", help="locate addresses with a MaxMind GeoLite2-City database")
    geo.add_argument("--simulated-geo", action="store_true", help="locate addresses with the simulator's fake table")
    parser.add_argument("--once", action="store_true", help="catch up, detect, save, and exit instead of following")
    args = parser.parse_args(argv)
    if args.poll <= 0 or args.lateness < 0:
        parser.error("--poll must be positive and --lateness cannot be negative")

    tz: Any = timezone.utc
    if args.tz.upper() != "UTC":
        try:
            from zoneinfo import ZoneInfo

            tz = ZoneInfo(args.tz)
        except Exception as exc:
            parser.error(f"cannot use timezone {args.tz!r}: {exc}")
    resolver: Optional[GeoResolver] = None
    try:
        rules = load_rules(args.rules)
        if args.simulated_geo:
            from siftlog.enrich import TableGeoResolver
            from siftlog.simulator import FAKE_GEO

            resolver = TableGeoResolver(FAKE_GEO)
        elif args.geoip:
            from siftlog.enrich import open_maxmind

            resolver = open_maxmind(args.geoip)
    except (RuleError, RuntimeError, OSError) as exc:
        parser.error(str(exc))

    def stop(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    # `kill` and systemd stop a process with SIGTERM, not Ctrl+C. Treat both the same,
    # so events still waiting in the ordering buffer are evaluated before exiting.
    try:
        previous = signal.signal(signal.SIGTERM, stop)
    except ValueError:  # not the main thread: signals cannot be handled here
        previous = None

    with EventStore(args.db) as store:
        watcher = Watcher(
            args.files, store, rules, lambda: PARSERS[args.source](year=args.year, tz=tz),
            lateness=args.lateness, resolver=resolver,
        )  # fmt: skip
        synced = watcher.start()
        print(
            f"caught up: {store.count()} events stored, {store.count_alerts()} alert(s) "
            f"({synced.new} new, {synced.updated} updated, {synced.reopened} reopened)",
            flush=True,
        )
        try:
            while not args.once:
                report = watcher.step()
                for alert in report.opened:
                    print(f"ALERT   {_describe(alert)}", flush=True)
                for alert in report.updated:
                    print(f"update  {_describe(alert)}", flush=True)
                if report.late_events:
                    print(f"note: {report.late_events} event(s) arrived too late to order; stored, not evaluated", flush=True)
                time.sleep(args.poll)
        except KeyboardInterrupt:
            print("stopping", flush=True)
        finally:
            watcher.close()
            if previous is not None:
                signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
