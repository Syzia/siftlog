"""Score alerts against the simulator's ground truth.

Two questions, answered separately.

**Did we catch what we should? (recall, per scenario)** A scenario labelled
``expect_alert`` is *detected* when the rule it names raised an alert, keyed on
the scenario's group, whose evidence includes that scenario's events.

**Is each alert worth an analyst's time? (precision, per alert)** Every event
the simulator emits is labelled with the scenario that produced it, so each
alert is judged on its own evidence:

* **false**: most of its evidence is benign traffic. This is the only kind that
  counts against precision.
* **duplicate**: it points at an attack this rule already raised an alert for.
  Real, but noise: "one attack, one alert" is part of the contract.
* **bonus**: the first alert on a real attack the rule was *not* expected to
  catch (a documented miss, or another rule's scenario). Counted as correct,
  because penalising a rule for catching an attack would be perverse.

Attacks labelled ``expect_alert: false`` are documented misses (low-and-slow).
They are left out of recall and reported as ``attack_recall``, so the gap is
visible rather than hidden.

Without per-event labels (``event_scenarios``) the scorer falls back to matching
on group key and time overlap, which is coarser.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from siftlog.engine.replay import Alert
from siftlog.simulator.core import ScenarioLabel


@dataclass(frozen=True)
class RuleScore:
    rule_id: str
    loaded: bool  # False: scenarios expect this rule but it is not among the rules run
    expected: int  # scenarios that should fire this rule
    detected: int  # ...of which this rule raised a matching alert
    alerts: int  # alerts this rule raised
    false_alerts: int
    duplicate_alerts: int
    bonus_alerts: int

    @property
    def precision(self) -> Optional[float]:
        return (self.alerts - self.false_alerts) / self.alerts if self.alerts else None

    @property
    def recall(self) -> Optional[float]:
        return self.detected / self.expected if self.expected else None


@dataclass(frozen=True)
class ScoreReport:
    rules: Tuple[RuleScore, ...]
    attacks: int  # every attack scenario, documented misses included
    documented_misses: Tuple[str, ...]  # attack scenarios not expected to alert
    missed: Tuple[str, ...]  # expected scenarios that got no alert
    false_alert_details: Tuple[str, ...]  # "rule on group_key", for debugging

    def rule(self, rule_id: str) -> RuleScore:
        for row in self.rules:
            if row.rule_id == rule_id:
                return row
        raise KeyError(rule_id)

    def _sum(self, name: str) -> int:
        return sum(getattr(row, name) for row in self.rules)

    @property
    def precision(self) -> Optional[float]:
        alerts = self._sum("alerts")
        return (alerts - self._sum("false_alerts")) / alerts if alerts else None

    @property
    def recall(self) -> Optional[float]:
        return self._sum("detected") / self._sum("expected") if self._sum("expected") else None

    @property
    def attack_recall(self) -> Optional[float]:
        """Detected attacks over ALL attacks, including the ones we knowingly miss."""
        return self._sum("detected") / self.attacks if self.attacks else None

    def to_markdown(self) -> str:
        lines = [
            "| Rule | Expected | Detected | Alerts | False | Duplicate | Precision | Recall |",
            "|------|---------:|---------:|-------:|------:|----------:|----------:|-------:|",
        ]
        for row in self.rules:
            name = f"`{row.rule_id}`" + ("" if row.loaded else " *(not implemented)*")
            lines.append(
                f"| {name} | {row.expected} | {row.detected} | {row.alerts} | {row.false_alerts} "
                f"| {row.duplicate_alerts} | {percent(row.precision)} | {percent(row.recall)} |"
            )
        lines.append(
            f"| **All** | {self._sum('expected')} | {self._sum('detected')} | {self._sum('alerts')} "
            f"| {self._sum('false_alerts')} | {self._sum('duplicate_alerts')} "
            f"| {percent(self.precision)} | {percent(self.recall)} |"
        )
        lines.append("")
        lines.append(
            f"Attack scenarios: {self.attacks}, detected {self._sum('detected')} "
            f"({percent(self.attack_recall)} of all attacks). "
            f"Documented misses (attacks not expected to alert): {len(self.documented_misses)}."
        )
        if self._sum("bonus_alerts"):
            lines.append(
                f"Bonus: {self._sum('bonus_alerts')} alert(s) on real attacks a rule was not expected to catch."
            )
        return "\n".join(lines)


def percent(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _overlaps(alert: Alert, label: ScenarioLabel) -> bool:
    return alert.first_seen <= label.end and alert.last_seen >= label.start


def score(
    labels: Sequence[ScenarioLabel],
    alerts: Iterable[Alert],
    rule_ids: Optional[Iterable[str]] = None,
    event_scenarios: Optional[Mapping[str, str]] = None,
) -> ScoreReport:
    """Score ``alerts`` against ``labels``.

    ``rule_ids`` are the rules that were run (defaults to those seen in
    ``alerts``). ``event_scenarios`` maps event id to the scenario id that
    produced it; give it whenever the data came from the simulator.
    """
    alerts = sorted(alerts, key=lambda a: (a.first_seen, a.rule_id, a.group_key))
    loaded = set(rule_ids) if rule_ids is not None else {a.rule_id for a in alerts}
    by_id = {label.id: label for label in labels}
    attack_ids = {label.id for label in labels if label.is_attack}
    expected = [label for label in labels if label.expect_alert]
    no_rule = "(no rule named)"

    counts: Dict[str, Dict[str, int]] = {}

    def row(rule_id: str) -> Dict[str, int]:
        return counts.setdefault(
            rule_id, dict.fromkeys(("expected", "detected", "alerts", "false", "duplicate", "bonus"), 0)
        )

    for rule_id in loaded:
        row(rule_id)
    for label in expected:
        row(label.rule_hint or no_rule)["expected"] += 1

    def attacks_behind(alert: Alert) -> Tuple[List[str], Set[str]]:
        """(attack scenarios this alert is about, largest share first; every scenario in its evidence)."""
        if event_scenarios is None:
            hits = [l.id for l in labels if l.is_attack and l.group_key == alert.group_key and _overlaps(alert, l)]
            return hits, set(hits)
        tally = Counter(event_scenarios.get(event_id) for event_id in alert.evidence_event_ids)
        total = sum(tally.values())
        from_attacks = sum(n for scenario, n in tally.items() if scenario in attack_ids)
        present = {scenario for scenario in tally if scenario is not None}
        if total == 0 or from_attacks * 2 < total:
            return [], present  # mostly benign evidence
        return [scenario for scenario, _ in tally.most_common() if scenario in attack_ids], present

    claimed: Set[Tuple[str, str]] = set()  # (rule id, attack scenario) already alerted on
    detected: Set[str] = set()
    false_details: List[str] = []
    for alert in alerts:
        entry = row(alert.rule_id)
        entry["alerts"] += 1
        about, present = attacks_behind(alert)
        if not about:
            entry["false"] += 1
            false_details.append(f"{alert.rule_id} on {alert.group_key}")
        else:
            claim = (alert.rule_id, about[0])
            if claim in claimed:
                entry["duplicate"] += 1
            else:
                claimed.add(claim)
                primary = by_id[about[0]]
                if not (primary.expect_alert and primary.rule_hint == alert.rule_id):
                    entry["bonus"] += 1
        for label in expected:
            if alert.rule_id == label.rule_hint and alert.group_key == label.group_key:
                if label.id in present if event_scenarios is not None else _overlaps(alert, label):
                    detected.add(label.id)

    for label in expected:
        if label.id in detected:
            row(label.rule_hint or no_rule)["detected"] += 1

    return ScoreReport(
        rules=tuple(
            RuleScore(
                rule_id=rule_id,
                loaded=rule_id in loaded,
                expected=c["expected"],
                detected=c["detected"],
                alerts=c["alerts"],
                false_alerts=c["false"],
                duplicate_alerts=c["duplicate"],
                bonus_alerts=c["bonus"],
            )
            for rule_id, c in sorted(counts.items())
        ),
        attacks=len(attack_ids),
        documented_misses=tuple(l.id for l in labels if l.is_attack and not l.expect_alert),
        missed=tuple(label.id for label in expected if label.id not in detected),
        false_alert_details=tuple(false_details),
    )


def merge(reports: Sequence[ScoreReport]) -> ScoreReport:
    """Add up reports from independent runs (for example one per simulator seed)."""
    names = ("expected", "detected", "alerts", "false_alerts", "duplicate_alerts", "bonus_alerts")
    totals: Dict[str, Dict[str, int]] = {}
    loaded: Dict[str, bool] = {}
    for report in reports:
        for r in report.rules:
            total = totals.setdefault(r.rule_id, dict.fromkeys(names, 0))
            for name in names:
                total[name] += getattr(r, name)
            loaded[r.rule_id] = loaded.get(r.rule_id, False) or r.loaded
    return ScoreReport(
        rules=tuple(RuleScore(rule_id=k, loaded=loaded[k], **t) for k, t in sorted(totals.items())),
        attacks=sum(r.attacks for r in reports),
        documented_misses=tuple(m for r in reports for m in r.documented_misses),
        missed=tuple(m for r in reports for m in r.missed),
        false_alert_details=tuple(m for r in reports for m in r.false_alert_details),
    )
