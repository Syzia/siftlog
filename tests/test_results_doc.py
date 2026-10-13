"""The published results must be what the code actually produces."""
import os
import unittest

from siftlog.engine import load_rules
from siftlog.evaluate import (
    PUBLISHED_SEEDS,
    PUBLISHED_SWEEPS,
    evaluate,
    simulated_dataset,
    sweep_markdown,
    threshold_sweep,
)

ROOT = os.path.dirname(os.path.dirname(__file__))
STALE = "docs/results.md is out of date: run `python -m siftlog.evaluate --published` and update it"


class ResultsDocTests(unittest.TestCase):
    def test_every_published_table_is_reproducible(self):
        with open(os.path.join(ROOT, "docs", "results.md"), encoding="utf-8") as fh:
            doc = fh.read()
        rules = load_rules(os.path.join(ROOT, "rules"))
        shipped = {rule.id: rule.threshold for rule in rules}
        datasets = [simulated_dataset(seed) for seed in range(1, PUBLISHED_SEEDS + 1)]

        self.assertIn(evaluate(rules, datasets).to_markdown(), doc, STALE)
        for rule_id, thresholds in PUBLISHED_SWEEPS:
            table = sweep_markdown(rule_id, threshold_sweep(rules, rule_id, list(thresholds), datasets), shipped[rule_id])
            self.assertIn(table, doc, f"{STALE} (sweep for {rule_id})")
        self.assertIn(f"{sum(len(d.events) for d in datasets):,} events", doc, STALE)


if __name__ == "__main__":
    unittest.main()
