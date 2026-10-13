# Siftlog

A small SIEM: ingest auth logs, normalize them into one event schema, and fire alerts from YAML detection rules (brute force, password spraying, credential stuffing, impossible travel).

> **Status:** detection works end to end on simulated data: parse, store, locate, run five rules, and score the alerts against ground truth. A honeypot is collecting real data for later. There is no API or dashboard yet.

## Design in one paragraph

Simulated traffic first, so every rule is tested against labelled attack and benign scenarios. SQLite and a single FastAPI process rather than Kafka and Elasticsearch. Detections are YAML data, not code, and the rule types follow Sigma's correlation types. The full design is in [docs/architecture.md](docs/architecture.md).

## Results so far

Across 50 independent simulations, the five rules raise **every alert they should, with no duplicates**. They are also wrong in two known, measured ways:

- **Precision is 85.7%.** Every false alert is the impossible-travel rule flagging a real user on a VPN. No speed threshold fixes it, because the VPN user and a thief both appear to teleport.
- **83.3% of all simulated attacks are detected.** The low-and-slow attack stays under every threshold.

These are simulated-data numbers and the thresholds were tuned against the simulator, so treat them as a correctness check, not a performance claim. The definitions, the gaps, and the sweeps that show where each rule breaks are in [docs/results.md](docs/results.md). A test regenerates that page's tables and fails if they drift.

## Build stages

| Stage | Deliverable | Status |
|-------|-------------|--------|
| 0 | Cowrie honeypot on an isolated VPS ([runbook](docs/honeypot.md)) | deployed 2026-10-13 |
| 1 | Labelled log simulator + SSH parser + event schema | done |
| 2 | SQLite event store + idempotent batch ingest | done |
| 3 | Replay-mode engine, `event_count` and `value_count` rules | done |
| 4 | `temporal_ordered` + `impossible_travel` rules, GeoIP enrichment | done |
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

# 3. add locations to the stored events (the travel rule needs them). --simulated uses
#    the simulator's fake table; real logs use --geoip GeoLite2-City.mmdb instead.
.venv/bin/python -m siftlog.enrich --db siftlog.db --simulated

# 4. run the rules over the stored events and score the alerts against ground truth
.venv/bin/python -m siftlog.engine --db siftlog.db --rules rules --labels sim.log.labels.json --log sim.log

# 5. measure the rules across 50 simulations, with sweeps of each rule's main setting
.venv/bin/python -m siftlog.evaluate --published
```

`--year` is required because classic syslog timestamps carry no year, and guessing would silently corrupt every timestamp.

The simulator emits six attack scenarios and five benign ones (typos, a NAT'd office, legitimate travel, a monitoring probe, a VPN user). Two are there to keep the results honest: `low_and_slow` is an attack the rules are known to miss, and `vpn_hop` is a benign user they are known to flag.

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
- **`temporal_ordered`** fires when a list of `steps` is satisfied in order, such as five failures and then a success. **`impossible_travel`** fires when two located logins for one user are too far apart for the time between them. See [`rules/`](rules/) for an example of each.
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
