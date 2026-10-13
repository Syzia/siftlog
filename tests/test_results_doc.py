"""The published results must be what the code actually produces."""
import os
import unittest

from siftlog.engine import load_rules
from siftlog.evaluate import (
    PUBLISHED_SEEDS,
    PUBLISHED_SWEEPS,
    evaluate,
    grouping_note,
    simulated_dataset,
    sweep_markdown,
    threshold_sweep,
)

ROOT = os.path.dirname(os.path.dirname(__file__))
STALE = "docs/results.md is out of date: run `python -m siftlog.evaluate --published` and update it"


class ResultsDocTests(unittest.TestCase):
    def test_every_published_number_is_reproducible(self):
        with open(os.path.join(ROOT, "docs", "results.md"), encoding="utf-8") as fh:
            doc = fh.read()
        rules = {rule.id: rule for rule in load_rules(os.path.join(ROOT, "rules"))}
        ordered = list(rules.values())
        datasets = [simulated_dataset(seed) for seed in range(1, PUBLISHED_SEEDS + 1)]

        headline = evaluate(ordered, datasets).to_markdown()
        self.assertIn(headline, doc, STALE)
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            self.assertIn(headline, fh.read(), "README.md results table is out of date")
        for rule_id, values in PUBLISHED_SWEEPS:
            table = sweep_markdown(rules[rule_id], threshold_sweep(ordered, rule_id, list(values), datasets))
            self.assertIn(table, doc, f"{STALE} (sweep for {rule_id})")
        self.assertIn(grouping_note(ordered, datasets), doc, STALE)
        self.assertIn(f"{sum(len(d.events) for d in datasets):,} events", doc, STALE)


if __name__ == "__main__":
    unittest.main()
