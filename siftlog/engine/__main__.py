"""CLI: python -m siftlog.engine --db siftlog.db --rules rules [--labels sim.log.labels.json]"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from typing import List, Optional

from siftlog.engine import ReplayEngine, RuleError, load_rules, score
from siftlog.simulator import load_labels
from siftlog.store import EventStore


def _when(text: str) -> datetime:
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m siftlog.engine",
        description="Replay detection rules over the events stored in a Siftlog database.",
    )
    parser.add_argument("--db", default="siftlog.db")
    parser.add_argument("--rules", default="rules", help="rule file or directory")
    parser.add_argument("--since", type=_when, help="ISO 8601, inclusive (UTC if no offset given)")
    parser.add_argument("--until", type=_when, help="ISO 8601, exclusive")
    parser.add_argument("--labels", help="simulator label file: also print precision and recall")
    parser.add_argument(
        "--log",
        help="with --labels: the simulated log that was ingested, so each alert is "
        "scored on its own evidence instead of only on group and time",
    )
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except (RuleError, OSError) as exc:
        parser.error(str(exc))
    with EventStore(args.db) as store:
        alerts = ReplayEngine(rules).run(store.iter_events(since=args.since, until=args.until))

    print(f"{len(alerts)} alert(s) from {len(rules)} rule(s)")
    for a in alerts:
        distinct = "" if a.distinct_count is None else f", {a.distinct_count} distinct"
        print(
            f"  [{a.severity:<8}] {a.rule_id:<26} {a.group_key:<18} "
            f"{a.first_seen:%Y-%m-%d %H:%M:%S} -> {a.last_seen:%H:%M:%S}  "
            f"{a.event_count} events{distinct}"
        )
    if args.labels:
        event_scenarios = None
        if args.log:
            from siftlog.evaluate import file_event_scenarios

            event_scenarios = file_event_scenarios(args.log, args.labels)
        print()
        print(score(load_labels(args.labels), alerts, [rule.id for rule in rules], event_scenarios).to_markdown())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
