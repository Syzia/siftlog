"""CLI: python -m siftlog.ingest sim.log --db siftlog.db --year 2026

Honeypot logs: python -m siftlog.ingest cowrie.json --source cowrie --db honeypot.db
"""
from __future__ import annotations

import argparse
from datetime import timezone
from typing import List, Optional

from siftlog.ingest.batch import ingest_file
from siftlog.parsers import PARSERS, ParserConfigError, build_parser
from siftlog.store import EventStore


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m siftlog.ingest",
        description="Parse log files and store the events in a SQLite database. Safe to re-run.",
    )
    parser.add_argument("files", nargs="+", help="log files (.gz is read transparently)")
    parser.add_argument("--db", default="siftlog.db", help="SQLite database to write (created if missing)")
    parser.add_argument("--source", choices=sorted(PARSERS), default="sshd", help="what wrote the log (default: sshd)")
    parser.add_argument(
        "--year",
        type=int,
        help="year of each file's first line. Required for sshd: classic syslog timestamps have no year, "
        "and guessing would silently corrupt every timestamp. Not needed for cowrie",
    )
    parser.add_argument(
        "--ignore-ip",
        action="append",
        default=[],
        metavar="ADDRESS",
        help="leave out lines from this address or network, such as your own; repeat for several",
    )
    parser.add_argument(
        "--show-ignored",
        action="store_true",
        help="list why lines were ignored, with a count for each reason",
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

    def fresh_parser():
        return build_parser(args.source, year=args.year, tz=tz, ignore_ips=args.ignore_ip)

    try:
        fresh_parser()  # fail on bad options before touching the database
    except ParserConfigError as exc:
        parser.error(str(exc))

    with EventStore(args.db) as store:
        for path in args.files:
            report = ingest_file(path, fresh_parser(), store, include_unterminated=args.include_unterminated)
            note = " (last line unterminated, skipped)" if report.skipped_unterminated_tail else ""
            print(
                f"{path}: {report.lines} lines -> {report.events_new} new events, "
                f"{report.events_duplicate} already stored, {report.ignored_total} ignored, "
                f"{report.dead_letters} dead letters{note}"
            )
            if args.show_ignored:
                for reason, count in sorted(report.ignored.items(), key=lambda item: (-item[1], item[0])):
                    print(f"    ignored {count:>7}  {reason}")
        print(f"{args.db}: {store.count()} events, {store.dead_letter_count()} dead letters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
