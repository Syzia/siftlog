# Siftlog

A small SIEM: ingest auth logs, normalize them into one event schema, and fire alerts from YAML detection rules (brute force, password spraying, credential stuffing, impossible travel).

> **Status:** detection works end to end on simulated data: parse, store, run rules, score the alerts against ground truth. A honeypot is collecting real data for later. There is no API or dashboard yet.

## Design in one paragraph

Simulated traffic first, so every rule is tested against labelled attack and benign scenarios. SQLite and a single FastAPI process rather than Kafka and Elasticsearch. Detections are YAML data, not code, and the rule types follow Sigma's correlation types. The full design is in [docs/architecture.md](docs/architecture.md).

## Results so far

Across 50 independent simulations, each of the three implemented rules raises **exactly one alert per attack and none on benign traffic**. Overall recall is **75%**, not 100%, because impossible travel has no rule yet, and one attack type (low-and-slow) is a documented miss, which puts detection at **60% of all simulated attacks**.

These are simulated-data numbers and the thresholds were tuned against the simulator, so treat them as a correctness check, not a performance claim. The definitions, the gaps, and the threshold sweeps that show where each rule breaks are in [docs/results.md](docs/results.md). A test regenerates that page's tables and fails if they drift.

## Build stages

| Stage | Deliverable | Status |
|-------|-------------|--------|
| 0 | Cowrie honeypot on an isolated VPS ([runbook](docs/honeypot.md)) | deployed 2026-10-13 |
| 1 | Labelled log simulator + SSH parser + event schema | done |
| 2 | SQLite event store + idempotent batch ingest | done |
| 3 | Replay-mode engine, `event_count` and `value_count` rules | done |
| 4 | `temporal` + `impossible_travel` rules, GeoIP enrichment | not started |
| 5 | FastAPI + episode-based alerts (**MVP**) | not started |
| 6 | Streaming mode + tail ingestor | not started |
| 7 | React dashboard (optional) | not started |
| 8 | Real data + web log parser | not started |
| 9 | Sigma rule import (stretch) | not started |

## Try it

Needs Python 3.9+ and PyYAML. A local virtualenv keeps it tidy (`.venv/` is git-ignored):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install PyYAML pytest
.venv/bin/python -m pytest
```

Then the whole pipeline, one step at a time:

```bash
# 1. generate a labelled log: sim.log + sim.log.labels.json (ground truth per line)
.venv/bin/python -m siftlog.simulator --seed 1234 --out sim.log

# 2. parse it into SQLite. Safe to re-run: nothing is counted twice, even if the
#    file was rotated, renamed or gzipped in between.
.venv/bin/python -m siftlog.ingest sim.log --db siftlog.db --year 2026

# 3. run the rules over the stored events and score the alerts against ground truth
.venv/bin/python -m siftlog.engine --db siftlog.db --rules rules --labels sim.log.labels.json --log sim.log

# 4. measure the rules across 50 simulations, with threshold sweeps
.venv/bin/python -m siftlog.evaluate --published
```

`--year` is required because classic syslog timestamps carry no year, and guessing would silently corrupt every timestamp.

The simulator emits five attack scenarios and four benign ones (typos, a NAT'd office, legitimate travel, a monitoring probe). One attack, `low_and_slow`, is deliberately under the default thresholds and labelled `expect_alert: false`: it is a documented miss, not a bug.

## Writing a rule

Rules live in [`rules/`](rules/), one YAML file each:

```yaml
id: ssh-password-spray
title: SSH password spraying
severity: high
type: value_count          # or event_count
filter:
  event_type: auth_failure
  source: sshd
group_by: [src_ip]
distinct: username         # value_count only: the field whose distinct values are counted
timespan: 10m
condition:
  gte: 8
mitre: [T1110.003]
```

- **`event_count`** fires on N matching events in the window; **`value_count`** on N *distinct values* of one field.
- **Windows slide.** They end at the newest event, so an attack straddling a clock boundary is still caught.
- **One attack is one alert.** An alert stays open while its condition holds and closes after a cooldown (default: the timespan). A later burst opens a new one.
- **Validation is strict.** An unknown key is an error, so a typo stops the engine rather than producing a rule that never fires.

## Parser behaviour worth knowing

Each line becomes an **event**, is **ignored** with a reason (understood, not security-relevant, or a duplicate of a line already counted), or becomes a **dead letter** (not understood, kept for inspection). Usernames are attacker-controlled, so source addresses are always taken from the end of the line, where sshd wrote them.

## Querying the store

```python
from datetime import datetime, timezone
from siftlog.store import EventStore

with EventStore("siftlog.db") as store:
    events = store.query(
        src_ip="203.0.113.5",
        event_type="auth_failure",
        since=datetime(2026, 3, 1, tzinfo=timezone.utc),  # inclusive
        until=datetime(2026, 3, 2, tzinfo=timezone.utc),  # exclusive
    )
```

Results come back in time order, with ties broken by position in the source file.

## Safety

This project handles attacker-controlled input. Only run it against logs from systems you own or have permission to monitor. No real logs, credentials or attack traffic belong in this repository: fixtures are sanitized and use documentation IP ranges (RFC 5737).
