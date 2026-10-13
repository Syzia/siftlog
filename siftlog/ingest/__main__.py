"""CLI: python -m siftlog.ingest sim.log --db siftlog.db --year 2026"""
from __future__ import annotations

import argparse
from datetime import timezone
from typing import List, Optional

from siftlog.ingest.batch import ingest_file
from siftlog.parsers import PARSERS
from siftlog.store import EventStore


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m siftlog.ingest",
        description="Parse log files and store the events in a SQLite database. Safe to re-run.",
    )
    parser.add_argument("files", nargs="+", help="log files (.gz is read transparently)")
    parser.add_argument("--db", default="siftlog.db", help="SQLite database to write (created if missing)")
    parser.add_argument("--source", choices=sorted(PARSERS), default="sshd")
    parser.add_argument(
        "--year",
        type=int,
        required=True,
        help="year of each file's first line: classic syslog timestamps have no year, "
        "and guessing would silently corrupt every timestamp",
    )
    parser.add_argument("--tz", default="UTC", help="timezone the host logged in, e.g. Europe/London")
    parser.add_argument(
        "--include-unterminated",
        action="store_true",
        help="also ingest a final line with no trailing newline (default: leave it for the next run)",
    )
    args = parser.parse_args(argv)

    if args.tz.upper() == "UTC":
        tz = timezone.utc
    else:
        try:
            from zoneinfo import ZoneInfo

            tz = ZoneInfo(args.tz)
        except Exception as exc:  # unknown zone, or no tz database on this machine
            parser.error(f"cannot use timezone {args.tz!r}: {exc}")

    with EventStore(args.db) as store:
        for path in args.files:
            report = ingest_file(
                path,
                PARSERS[args.source](year=args.year, tz=tz),
                store,
                include_unterminated=args.include_unterminated,
            )
            note = " (last line unterminated, skipped)" if report.skipped_unterminated_tail else ""
            print(
                f"{path}: {report.lines} lines -> {report.events_new} new events, "
                f"{report.events_duplicate} already stored, {report.ignored_total} ignored, "
                f"{report.dead_letters} dead letters{note}"
            )
        print(f"{args.db}: {store.count()} events, {store.dead_letter_count()} dead letters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
