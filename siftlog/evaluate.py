"""Measure the rules against many independent simulations.

    python -m siftlog.evaluate --rules rules --seeds 50
    python -m siftlog.evaluate --rules rules --seeds 50 --sweep ssh-brute-force:3,5,10,20,45

Each seed is a separate simulated world run through the real pipeline (parser,
event store, engine), then scored against that simulation's labels. One seed
proves little; many seeds vary the timing, addresses and overlaps.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import replace
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from siftlog.engine import (
    IMPOSSIBLE_TRAVEL,
    TEMPORAL_ORDERED,
    ReplayEngine,
    Rule,
    RuleError,
    ScoreReport,
    load_rules,
    merge,
    score,
)
from siftlog.engine.scoring import RuleScore, percent
from siftlog.enrich import TableGeoResolver, enrich
from siftlog.events import Event, make_event_id
from siftlog.ingest import file_identity, iter_file_lines
from siftlog.parsers import SshdParser
from siftlog.simulator import FAKE_GEO, ScenarioLabel, simulate
from siftlog.store import EventStore


# What docs/results.md publishes. A test regenerates these and fails if the doc is stale.
PUBLISHED_SEEDS = 50
PUBLISHED_SWEEPS = (
    ("ssh-brute-force", (3, 5, 10, 20, 26, 45)),
    ("ssh-password-spray", (3, 6, 8, 12, 31)),
    ("ssh-credential-stuffing", (3, 7, 15, 25, 28)),
    ("ssh-success-after-failures", (1, 3, 5, 25, 26)),
    ("ssh-impossible-travel", (300, 900, 5000, 50000)),
)


class Dataset(NamedTuple):
    events: List[Event]
    labels: List[ScenarioLabel]
    event_scenarios: Dict[str, str]  # event id -> id of the scenario that produced it


def simulated_dataset(seed: int) -> Dataset:
    """One simulated world, parsed and read back from the store in engine order."""
    sim = simulate(seed=seed)
    parser = SshdParser(year=2026)  # the simulator's default window starts 2026-03-01
    resolver = TableGeoResolver(FAKE_GEO)  # the simulator's addresses are in no real GeoIP database
    events: List[Event] = []
    for line_number, line in enumerate(sim.lines):
        result = parser.parse_line(line, f"sim:{seed}", line_number)
        if result.dead_letter is not None:
            raise RuntimeError(f"seed {seed}: simulator produced an unparseable line: {result.dead_letter.raw!r}")
        events.extend(enrich(event, resolver) for event in result.events)
    with EventStore() as store:
        store.add_events(events)
        ordered = list(store.iter_events())
    return Dataset(ordered, sim.labels, {e.id: sim.line_scenarios[e.offset] for e in ordered})


def file_event_scenarios(log_path: str, labels_path: str, source_id: Optional[str] = None) -> Dict[str, str]:
    """Event id -> scenario id for a log written by the simulator and ingested from disk.

    Ingest derives event ids from (stream identity, byte offset), so this walks
    the file the same way and pairs each line with its label.
    """
    with open(labels_path, "r", encoding="utf-8") as fh:
        line_scenarios = json.load(fh)["line_scenarios"]
    sid = source_id or file_identity(log_path)
    return {
        make_event_id(sid, offset): line_scenarios[number]
        for number, (offset, _) in enumerate(iter_file_lines(log_path))
        if number < len(line_scenarios)
    }


def evaluate(rules: Sequence[Rule], datasets: Iterable[Dataset]) -> ScoreReport:
    rule_ids = [rule.id for rule in rules]
    return merge(
        [
            score(d.labels, ReplayEngine(rules).run(d.events), rule_ids, d.event_scenarios)
            for d in datasets
        ]
    )


def knob(rule: Rule) -> Tuple[str, float]:
    """The one number most worth tuning for a rule: (what it is called, its shipped value)."""
    if rule.type == TEMPORAL_ORDERED:
        return "first-step threshold", rule.steps[0].threshold
    if rule.type == IMPOSSIBLE_TRAVEL:
        return "max_speed_kmh", rule.max_speed_kmh  # type: ignore[return-value]
    return "threshold", rule.threshold


def with_knob(rule: Rule, value: float) -> Rule:
    if rule.type == TEMPORAL_ORDERED:
        return replace(rule, steps=(replace(rule.steps[0], threshold=int(value)),) + rule.steps[1:])
    if rule.type == IMPOSSIBLE_TRAVEL:
        return replace(rule, max_speed_kmh=float(value))
    return replace(rule, threshold=int(value))


def threshold_sweep(
    rules: Sequence[Rule], rule_id: str, values: Sequence[float], datasets: Sequence[Dataset]
) -> List[Tuple[float, RuleScore]]:
    """Re-run with one rule's main knob varied: shows the precision/recall trade-off."""
    if rule_id not in {rule.id for rule in rules}:
        raise KeyError(rule_id)
    rows = []
    for value in values:
        varied = [with_knob(rule, value) if rule.id == rule_id else rule for rule in rules]
        rows.append((value, evaluate(varied, datasets).rule(rule_id)))
    return rows


def sweep_markdown(rule: Rule, rows: Sequence[Tuple[float, RuleScore]]) -> str:
    name, shipped = knob(rule)
    lines = [
        f"| `{rule.id}` {name} | Detected | Alerts | False | Duplicate | Bonus | Precision | Recall |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for value, row in rows:
        mark = " (shipped)" if value == shipped else ""
        lines.append(
            f"| {value:g}{mark} | {row.detected} / {row.expected} | {row.alerts} | {row.false_alerts} "
            f"| {row.duplicate_alerts} | {row.bonus_alerts} | {percent(row.precision)} | {percent(row.recall)} |"
        )
    return "\n".join(lines)


def grouping_note(rules: Sequence[Rule], datasets: Sequence[Dataset]) -> str:
    """Measure why ssh-success-after-failures groups by address AND username."""
    rule_id = "ssh-success-after-failures"
    by_address = [replace(r, group_by=("src_ip",)) if r.id == rule_id else r for r in rules]
    row = evaluate(by_address, datasets).rule(rule_id)
    shipped = evaluate(rules, datasets).rule(rule_id)
    return (
        f"Grouped by address and username (shipped), `{rule_id}` raises {shipped.false_alerts} false alerts "
        f"across these runs. Grouped by address alone it raises {row.false_alerts}."
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m siftlog.evaluate", description=__doc__.splitlines()[0])
    parser.add_argument("--rules", default="rules", help="rule file or directory")
    parser.add_argument("--seeds", type=int, default=50, help="number of independent simulations")
    parser.add_argument("--sweep", action="append", default=[], metavar="RULE_ID:N,N,...",
                        help="also vary one rule's threshold, e.g. ssh-brute-force:3,5,10,20,45")
    parser.add_argument("--published", action="store_true",
                        help="reproduce exactly the tables in docs/results.md")
    args = parser.parse_args(argv)
    if args.published:
        args.seeds = PUBLISHED_SEEDS
        args.sweep = [f"{rule_id}:{','.join(map(str, values))}" for rule_id, values in PUBLISHED_SWEEPS]

    try:
        rules = load_rules(args.rules)
    except (RuleError, OSError) as exc:
        parser.error(str(exc))
    datasets = [simulated_dataset(seed) for seed in range(1, args.seeds + 1)]
    report = evaluate(rules, datasets)
    print(f"Evaluated {len(rules)} rule(s) over {args.seeds} simulations "
          f"({sum(len(d.events) for d in datasets)} events).\n")
    print(report.to_markdown())
    for spec in args.sweep:
        rule_id, _, values = spec.partition(":")
        try:
            thresholds = [int(v) for v in values.split(",")]
            rule = next(rule for rule in rules if rule.id == rule_id)
        except (ValueError, StopIteration):
            parser.error(f"bad --sweep {spec!r}: expected a loaded RULE_ID followed by :N,N,...")
        print()
        print(sweep_markdown(rule, threshold_sweep(rules, rule_id, thresholds, datasets)))
    if args.published:
        print()
        print(grouping_note(rules, datasets))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
