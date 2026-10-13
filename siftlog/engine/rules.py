"""Detection rules: YAML data, not code.

Rule types follow Sigma's correlation types where one exists, so a later Sigma
import is mostly field mapping:

* ``event_count``: N matching events within ``timespan``, per group.
* ``value_count``: N *distinct values* of one field within ``timespan``, per group.
* ``temporal_ordered``: a sequence of steps, each needing N matching events, in
  order, all within ``timespan``, per group ("failures, then a success").
* ``impossible_travel`` (a Siftlog extension): two located events for one group
  that are too far apart for the time between them.

Validation is strict on purpose. A misspelt key in a detection rule should stop
the engine from starting, not produce a rule that quietly never fires.
"""
from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

from siftlog.events import Event

EVENT_COUNT = "event_count"
VALUE_COUNT = "value_count"
TEMPORAL_ORDERED = "temporal_ordered"
IMPOSSIBLE_TRAVEL = "impossible_travel"
COUNT_TYPES = (EVENT_COUNT, VALUE_COUNT)
RULE_TYPES = COUNT_TYPES + (TEMPORAL_ORDERED, IMPOSSIBLE_TRAVEL)
SEVERITIES = ("low", "medium", "high", "critical")
# Event fields a rule may filter, group or count on.
EVENT_FIELDS = ("event_type", "source", "src_ip", "username", "host", "outcome")

_KEYS = {
    "id", "title", "description", "severity", "type", "filter", "group_by", "distinct",
    "timespan", "cooldown", "condition", "mitre", "steps", "max_speed_kmh", "min_distance_km",
}  # fmt: skip
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

Filter = Mapping[str, Tuple[str, ...]]


class RuleError(ValueError):
    """A rule file is malformed. The message says which file and why."""


def _passes(event: Event, rule_filter: Filter) -> bool:
    return all(getattr(event, name) in accepted for name, accepted in rule_filter.items())


@dataclass(frozen=True)
class Step:
    """One stage of a temporal_ordered rule: ``threshold`` events matching ``filter``."""

    filter: Filter
    threshold: int = 1

    def matches(self, event: Event) -> bool:
        return _passes(event, self.filter)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    type: str
    group_by: Tuple[str, ...]
    timespan: timedelta
    threshold: int  # count rules only; 1 and unused for the others
    op: str = "gte"  # "gte" or "gt"
    # field -> accepted values; an event must match every field. For temporal_ordered
    # this is the part common to all steps.
    filter: Filter = field(default_factory=dict)
    distinct: Optional[str] = None  # value_count only: the field whose distinct values are counted
    cooldown: Optional[timedelta] = None
    severity: str = "medium"
    mitre: Tuple[str, ...] = ()
    description: str = ""
    steps: Tuple[Step, ...] = ()  # temporal_ordered only
    max_speed_kmh: Optional[float] = None  # impossible_travel only
    min_distance_km: float = 0.0  # impossible_travel only

    @property
    def effective_cooldown(self) -> timedelta:
        return self.timespan if self.cooldown is None else self.cooldown

    def matches(self, event: Event) -> bool:
        return _passes(event, self.filter)

    def group_key(self, event: Event) -> Optional[str]:
        """The value(s) this event is grouped under, or None if it lacks one."""
        parts = [getattr(event, name) for name in self.group_by]
        if any(part is None for part in parts):
            return None
        return "|".join(parts)

    def holds(self, metric: int) -> bool:
        return metric > self.threshold if self.op == "gt" else metric >= self.threshold


def parse_timespan(text: Any, what: str, origin: str) -> timedelta:
    match = _TIMESPAN.match(text) if isinstance(text, str) else None
    if match is None or int(match.group(1)) == 0:
        raise RuleError(f"{origin}: {what} must look like 30s, 5m, 1h or 1d, got {text!r}")
    return timedelta(seconds=int(match.group(1)) * _SECONDS[match.group(2)])


def _fields(value: Any, what: str, origin: str) -> Tuple[str, ...]:
    names = [value] if isinstance(value, str) else value
    if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
        raise RuleError(f"{origin}: {what} must be a field name or a non-empty list of them")
    for name in names:
        if name not in EVENT_FIELDS:
            raise RuleError(f"{origin}: {what} uses unknown field {name!r}; choose from {', '.join(EVENT_FIELDS)}")
    return tuple(names)


def _filter(raw: Any, what: str, origin: str) -> Dict[str, Tuple[str, ...]]:
    if not isinstance(raw, dict):
        raise RuleError(f"{origin}: {what} must be a mapping of field to value(s)")
    parsed: Dict[str, Tuple[str, ...]] = {}
    for name, accepted in raw.items():
        if name not in EVENT_FIELDS:
            raise RuleError(f"{origin}: {what} uses unknown field {name!r}; choose from {', '.join(EVENT_FIELDS)}")
        values = accepted if isinstance(accepted, list) else [accepted]
        if not values or any(isinstance(v, (dict, list)) or v is None for v in values):
            raise RuleError(f"{origin}: {what}.{name} must be a value or a non-empty list of values")
        parsed[name] = tuple(str(v) for v in values)
    return parsed


def _threshold(condition: Any, ops: Sequence[str], what: str, origin: str) -> Tuple[str, int, Optional[Any]]:
    """Parse ``{gte: N}`` (optionally with Sigma's ``field``). Returns (op, N, field)."""
    if not isinstance(condition, dict):
        raise RuleError(f"{origin}: {what} must be a mapping such as {{gte: 10}}")
    condition = dict(condition)
    counted = condition.pop("field", None)
    present = [op for op in ops if op in condition]
    if len(present) != 1 or len(condition) != 1:
        raise RuleError(f"{origin}: {what} needs exactly one of {' or '.join(ops)}")
    value = condition[present[0]]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RuleError(f"{origin}: {what}.{present[0]} must be a positive integer, got {value!r}")
    return present[0], value, counted


def _number(value: Any, what: str, origin: str, minimum: float, exclusive: bool) -> float:
    ok = not isinstance(value, bool) and isinstance(value, (int, float))
    if not ok or value < minimum or (exclusive and value == minimum):
        bound = f"greater than {minimum:g}" if exclusive else f"at least {minimum:g}"
        raise RuleError(f"{origin}: {what} must be a number {bound}, got {value!r}")
    return float(value)


def _forbid(data: Mapping[str, Any], keys: Sequence[str], origin: str) -> None:
    present = [key for key in keys if key in data]
    if present:
        raise RuleError(f"{origin}: {', '.join(map(repr, present))} does not apply to a {data['type']} rule")


def parse_rule(data: Any, origin: str = "<rule>") -> Rule:
    if not isinstance(data, dict):
        raise RuleError(f"{origin}: a rule must be a mapping, got {type(data).__name__}")
    data = dict(data)
    if "group-by" in data:  # Sigma spelling
        if "group_by" in data:
            raise RuleError(f"{origin}: give group_by or group-by, not both")
        data["group_by"] = data.pop("group-by")
    unknown = sorted(set(data) - _KEYS)
    if unknown:
        raise RuleError(f"{origin}: unknown key(s) {', '.join(map(repr, unknown))}")
    for required in ("id", "title", "type", "group_by", "timespan"):
        if required not in data:
            raise RuleError(f"{origin}: missing required key {required!r}")

    rule_id, title, kind = data["id"], data["title"], data["type"]
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise RuleError(f"{origin}: id must be a non-empty string")
    origin = f"{origin} [{rule_id}]"
    if not isinstance(title, str) or not title.strip():
        raise RuleError(f"{origin}: title must be a non-empty string")
    if kind not in RULE_TYPES:
        raise RuleError(f"{origin}: type must be one of {', '.join(RULE_TYPES)}, got {kind!r}")

    severity = data.get("severity", "medium")
    if severity not in SEVERITIES:
        raise RuleError(f"{origin}: severity must be one of {', '.join(SEVERITIES)}, got {severity!r}")
    mitre = data.get("mitre", [])
    if not isinstance(mitre, list) or not all(isinstance(m, str) for m in mitre):
        raise RuleError(f"{origin}: mitre must be a list of technique ids")
    description = data.get("description", "")
    if not isinstance(description, str):
        raise RuleError(f"{origin}: description must be a string")

    common: Dict[str, Any] = dict(
        id=rule_id,
        title=title,
        type=kind,
        group_by=_fields(data["group_by"], "group_by", origin),
        timespan=parse_timespan(data["timespan"], "timespan", origin),
        filter=_filter(data.get("filter", {}), "filter", origin),
        cooldown=parse_timespan(data["cooldown"], "cooldown", origin) if "cooldown" in data else None,
        severity=severity,
        mitre=tuple(mitre),
        description=description,
    )

    if kind in COUNT_TYPES:
        _forbid(data, ("steps", "max_speed_kmh", "min_distance_km"), origin)
        if "condition" not in data:
            raise RuleError(f"{origin}: missing required key 'condition'")
        op, threshold, counted = _threshold(data["condition"], ("gte", "gt"), "condition", origin)
        distinct = data.get("distinct")
        if counted is not None:  # Sigma puts the counted field inside the condition
            if distinct is not None and distinct != counted:
                raise RuleError(f"{origin}: distinct and condition.field disagree")
            distinct = counted
        if kind == VALUE_COUNT:
            if distinct is None:
                raise RuleError(f"{origin}: a value_count rule needs 'distinct' (the field whose values are counted)")
            names = _fields(distinct, "distinct", origin)
            if len(names) != 1:
                raise RuleError(f"{origin}: distinct must be a single field")
            distinct = names[0]
        elif distinct is not None:
            raise RuleError(f"{origin}: 'distinct' only applies to value_count rules")
        return Rule(threshold=threshold, op=op, distinct=distinct, **common)

    if kind == TEMPORAL_ORDERED:
        _forbid(data, ("condition", "distinct", "max_speed_kmh", "min_distance_km"), origin)
        raw_steps = data.get("steps")
        if not isinstance(raw_steps, list) or len(raw_steps) < 2:
            raise RuleError(f"{origin}: a temporal_ordered rule needs 'steps', a list of at least two")
        steps: List[Step] = []
        for number, raw in enumerate(raw_steps, 1):
            where = f"steps[{number}]"
            if not isinstance(raw, dict) or set(raw) - {"filter", "condition"}:
                raise RuleError(f"{origin}: {where} must be a mapping with 'filter' and optionally 'condition'")
            step_filter = _filter(raw.get("filter"), f"{where}.filter", origin)
            if not step_filter:
                raise RuleError(f"{origin}: {where}.filter must not be empty")
            threshold = 1
            if "condition" in raw:
                _, threshold, counted = _threshold(raw["condition"], ("gte",), f"{where}.condition", origin)
                if counted is not None:
                    raise RuleError(f"{origin}: {where}.condition does not take 'field'")
            steps.append(Step(filter=step_filter, threshold=threshold))
        return Rule(threshold=1, steps=tuple(steps), **common)

    _forbid(data, ("condition", "distinct", "steps"), origin)
    if "max_speed_kmh" not in data:
        raise RuleError(f"{origin}: an impossible_travel rule needs 'max_speed_kmh'")
    return Rule(
        threshold=1,
        max_speed_kmh=_number(data["max_speed_kmh"], "max_speed_kmh", origin, 0, exclusive=True),
        min_distance_km=_number(data.get("min_distance_km", 0), "min_distance_km", origin, 0, exclusive=False),
        **common,
    )


def load_rules(path: str) -> List[Rule]:
    """Load one rule file, or every ``*.yml`` / ``*.yaml`` in a directory.

    Files are read in name order and may hold several ``---`` separated rules.
    Rule ids must be unique across everything loaded.
    """
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.yml")) + glob.glob(os.path.join(path, "*.yaml")))
        if not files:
            raise RuleError(f"{path}: no .yml or .yaml rule files found")
    else:
        files = [path]

    rules: List[Rule] = []
    seen: Dict[str, str] = {}
    for file in files:
        with open(file, "r", encoding="utf-8") as fh:
            try:
                # safe_load only: a rule file must never be able to construct Python objects.
                documents = [doc for doc in yaml.safe_load_all(fh) if doc is not None]
            except yaml.YAMLError as exc:
                raise RuleError(f"{file}: not valid YAML: {exc}") from exc
        if not documents:
            raise RuleError(f"{file}: contains no rule")
        for document in documents:
            rule = parse_rule(document, origin=file)
            if rule.id in seen:
                raise RuleError(f"{file}: duplicate rule id {rule.id!r} (also in {seen[rule.id]})")
            seen[rule.id] = file
            rules.append(rule)
    return rules
