"""Detection rules: YAML data, not code.

Rule types follow Sigma's correlation types so a later Sigma import is mostly
field mapping:

* ``event_count``: N matching events within ``timespan``, per group.
* ``value_count``: N *distinct values* of one field within ``timespan``, per group.

Validation is strict on purpose. A misspelt key in a detection rule should stop
the engine from starting, not produce a rule that quietly never fires.
"""
from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

from siftlog.events import Event

EVENT_COUNT = "event_count"
VALUE_COUNT = "value_count"
RULE_TYPES = (EVENT_COUNT, VALUE_COUNT)
SEVERITIES = ("low", "medium", "high", "critical")
# Event fields a rule may filter, group or count on.
EVENT_FIELDS = ("event_type", "source", "src_ip", "username", "host", "outcome")

_KEYS = {
    "id", "title", "description", "severity", "type", "filter", "group_by",
    "distinct", "timespan", "cooldown", "condition", "mitre",
}  # fmt: skip
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class RuleError(ValueError):
    """A rule file is malformed. The message says which file and why."""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    type: str
    group_by: Tuple[str, ...]
    timespan: timedelta
    threshold: int
    op: str = "gte"  # "gte" or "gt"
    # field -> accepted values; an event must match every field.
    filter: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    distinct: Optional[str] = None  # value_count only: the field whose distinct values are counted
    cooldown: Optional[timedelta] = None
    severity: str = "medium"
    mitre: Tuple[str, ...] = ()
    description: str = ""

    @property
    def effective_cooldown(self) -> timedelta:
        return self.timespan if self.cooldown is None else self.cooldown

    def matches(self, event: Event) -> bool:
        return all(getattr(event, name) in accepted for name, accepted in self.filter.items())

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
    for required in ("id", "title", "type", "group_by", "timespan", "condition"):
        if required not in data:
            raise RuleError(f"{origin}: missing required key {required!r}")

    rule_id, title = data["id"], data["title"]
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise RuleError(f"{origin}: id must be a non-empty string")
    origin = f"{origin} [{rule_id}]"
    if not isinstance(title, str) or not title.strip():
        raise RuleError(f"{origin}: title must be a non-empty string")
    if data["type"] not in RULE_TYPES:
        raise RuleError(f"{origin}: type must be one of {', '.join(RULE_TYPES)}, got {data['type']!r}")

    raw_filter = data.get("filter", {})
    if not isinstance(raw_filter, dict):
        raise RuleError(f"{origin}: filter must be a mapping of field to value(s)")
    rule_filter: Dict[str, Tuple[str, ...]] = {}
    for name, accepted in raw_filter.items():
        if name not in EVENT_FIELDS:
            raise RuleError(f"{origin}: filter uses unknown field {name!r}; choose from {', '.join(EVENT_FIELDS)}")
        values = accepted if isinstance(accepted, list) else [accepted]
        if not values or any(isinstance(v, (dict, list)) or v is None for v in values):
            raise RuleError(f"{origin}: filter.{name} must be a value or a non-empty list of values")
        rule_filter[name] = tuple(str(v) for v in values)

    condition = data["condition"]
    if not isinstance(condition, dict):
        raise RuleError(f"{origin}: condition must be a mapping such as {{gte: 10}}")
    condition = dict(condition)
    condition_field = condition.pop("field", None)  # Sigma puts the counted field here
    ops = [op for op in ("gte", "gt") if op in condition]
    if len(ops) != 1 or len(condition) != 1:
        raise RuleError(f"{origin}: condition needs exactly one of gte or gt")
    threshold = condition[ops[0]]
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise RuleError(f"{origin}: condition.{ops[0]} must be a positive integer, got {threshold!r}")

    distinct = data.get("distinct")
    if condition_field is not None:
        if distinct is not None and distinct != condition_field:
            raise RuleError(f"{origin}: distinct and condition.field disagree")
        distinct = condition_field
    if data["type"] == VALUE_COUNT:
        if distinct is None:
            raise RuleError(f"{origin}: a value_count rule needs 'distinct' (the field whose values are counted)")
        distinct = _fields(distinct, "distinct", origin)
        if len(distinct) != 1:
            raise RuleError(f"{origin}: distinct must be a single field")
        distinct = distinct[0]
    elif distinct is not None:
        raise RuleError(f"{origin}: 'distinct' only applies to value_count rules")

    severity = data.get("severity", "medium")
    if severity not in SEVERITIES:
        raise RuleError(f"{origin}: severity must be one of {', '.join(SEVERITIES)}, got {severity!r}")
    mitre = data.get("mitre", [])
    if not isinstance(mitre, list) or not all(isinstance(m, str) for m in mitre):
        raise RuleError(f"{origin}: mitre must be a list of technique ids")
    description = data.get("description", "")
    if not isinstance(description, str):
        raise RuleError(f"{origin}: description must be a string")

    return Rule(
        id=rule_id,
        title=title,
        type=data["type"],
        group_by=_fields(data["group_by"], "group_by", origin),
        timespan=parse_timespan(data["timespan"], "timespan", origin),
        threshold=threshold,
        op=ops[0],
        filter=rule_filter,
        distinct=distinct,
        cooldown=parse_timespan(data["cooldown"], "cooldown", origin) if "cooldown" in data else None,
        severity=severity,
        mitre=tuple(mitre),
        description=description,
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
