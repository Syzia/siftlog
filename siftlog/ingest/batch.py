"""Batch ingest: read a file once, parse it, and store events and dead letters."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from siftlog.events import DeadLetter, Event
from siftlog.ingest.reader import file_identity, iter_file_records
from siftlog.store import EventStore


@dataclass
class IngestReport:
    path: str
    source_id: str
    lines: int = 0
    events_parsed: int = 0
    events_new: int = 0
    ignored: Dict[str, int] = field(default_factory=dict)
    dead_letters: int = 0
    dead_letters_new: int = 0
    # The file's last line had no trailing newline, so it may still be being
    # written. It was left alone; a later ingest picks it up once complete.
    skipped_unterminated_tail: bool = False

    @property
    def events_duplicate(self) -> int:
        return self.events_parsed - self.events_new

    @property
    def ignored_total(self) -> int:
        return sum(self.ignored.values())


def ingest_file(
    path: str,
    parser,
    store: EventStore,
    *,
    source_id: Optional[str] = None,
    chunk_size: int = 5000,
    include_unterminated: bool = False,
) -> IngestReport:
    """Parse ``path`` with ``parser`` and write the results to ``store``.

    Safe to repeat: event ids come from (stream identity, byte offset), so
    re-ingesting a file, a rotated or compressed copy of it, or a longer version
    of it only adds lines that are actually new. Writes are committed per chunk,
    so an interrupted run can simply be run again.

    ``parser`` must be fresh for each file (its year-rollover state is
    per-stream) and exposes ``parse_line(line, source_id, offset)``.
    """
    sid = source_id or file_identity(path)
    report = IngestReport(path=path, source_id=sid)
    events: List[Event] = []
    letters: List[DeadLetter] = []

    def flush() -> None:
        if events:
            report.events_new += store.add_events(events)
            events.clear()
        if letters:
            report.dead_letters_new += store.add_dead_letters(letters)
            letters.clear()

    for offset, line, terminated in iter_file_records(path):
        if not terminated and not include_unterminated:
            report.skipped_unterminated_tail = True
            continue
        report.lines += 1
        result = parser.parse_line(line, sid, offset)
        if result.events:
            events.extend(result.events)
            report.events_parsed += len(result.events)
        elif result.dead_letter is not None:
            letters.append(result.dead_letter)
            report.dead_letters += 1
        elif result.ignored is not None:
            report.ignored[result.ignored] = report.ignored.get(result.ignored, 0) + 1
        if len(events) >= chunk_size or len(letters) >= chunk_size:
            flush()
    flush()
    return report
