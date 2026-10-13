# Siftlog

A small SIEM: ingest auth logs, normalize them into one event schema, and fire alerts from YAML detection rules (brute force, password spraying, credential stuffing, impossible travel).

> **Status: early development.** Nothing here is usable yet. The README, threat model and results table get written at stage 5 (MVP).

## Design in one paragraph

Simulated traffic first, so every rule is tested against labelled attack and benign scenarios. SQLite and a single FastAPI process rather than Kafka and Elasticsearch. Detections are YAML data, not code, and the rule types follow Sigma's correlation types. The full design is in [docs/architecture.md](docs/architecture.md).

## Build stages

| Stage | Deliverable | Status |
|-------|-------------|--------|
| 0 | Cowrie honeypot on an isolated VPS | not started |
| 1 | Labelled log simulator + SSH parser + event schema | done |
| 2 | SQLite event store + idempotent batch ingest | not started |
| 3 | Replay-mode engine, `event_count` and `value_count` rules | not started |
| 4 | `temporal` + `impossible_travel` rules, GeoIP enrichment | not started |
| 5 | FastAPI + episode-based alerts (**MVP**) | not started |
| 6 | Streaming mode + tail ingestor | not started |
| 7 | React dashboard (optional) | not started |
| 8 | Real data + web log parser | not started |
| 9 | Sigma rule import (stretch) | not started |

## Try it

Needs Python 3.9+ and nothing else (stdlib only so far).

```bash
# run the tests
python3 -m unittest discover -s tests -t .

# generate a labelled log: sim.log + sim.log.labels.json (ground truth per scenario)
python3 -m siftlog.simulator --seed 1234 --out sim.log
```

The simulator emits five attack scenarios and four benign ones (typos, a NAT'd office, legitimate travel, a monitoring probe). One attack, `low_and_slow`, is deliberately under the default thresholds and labelled `expect_alert: false`: it is a documented miss, not a bug.

## Parser behaviour worth knowing

Each line becomes an **event**, is **ignored** with a reason (understood, not security-relevant, or a duplicate of a line already counted), or becomes a **dead letter** (not understood, kept for inspection). Usernames are attacker-controlled, so source addresses are always taken from the end of the line, where sshd wrote them.

## Safety

This project handles attacker-controlled input. Only run it against logs from systems you own or have permission to monitor. No real logs, credentials or attack traffic belong in this repository: fixtures are sanitized and use documentation IP ranges (RFC 5737).
