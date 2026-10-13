"""Detection engine: YAML rules, replay evaluation, and scoring against ground truth."""
from siftlog.engine.replay import MAX_EVIDENCE, Alert, ReplayEngine, run_rules
from siftlog.engine.rules import (
    EVENT_COUNT,
    IMPOSSIBLE_TRAVEL,
    TEMPORAL_ORDERED,
    VALUE_COUNT,
    Rule,
    RuleError,
    Step,
    load_rules,
    parse_rule,
)
from siftlog.engine.scoring import RuleScore, ScoreReport, merge, score
from siftlog.engine.stream import ReorderBuffer, StreamingEngine

__all__ = [
    "EVENT_COUNT",
    "IMPOSSIBLE_TRAVEL",
    "MAX_EVIDENCE",
    "TEMPORAL_ORDERED",
    "VALUE_COUNT",
    "Alert",
    "ReorderBuffer",
    "ReplayEngine",
    "Rule",
    "RuleError",
    "RuleScore",
    "ScoreReport",
    "Step",
    "StreamingEngine",
    "load_rules",
    "merge",
    "parse_rule",
    "run_rules",
    "score",
]
