"""Detection engine: YAML rules, replay evaluation, and scoring against ground truth."""
from siftlog.engine.replay import MAX_EVIDENCE, Alert, ReplayEngine, run_rules
from siftlog.engine.rules import (
    EVENT_COUNT,
    VALUE_COUNT,
    Rule,
    RuleError,
    load_rules,
    parse_rule,
)
from siftlog.engine.scoring import RuleScore, ScoreReport, merge, score

__all__ = [
    "EVENT_COUNT",
    "MAX_EVIDENCE",
    "VALUE_COUNT",
    "Alert",
    "ReplayEngine",
    "Rule",
    "RuleError",
    "RuleScore",
    "ScoreReport",
    "load_rules",
    "merge",
    "parse_rule",
    "run_rules",
    "score",
]
