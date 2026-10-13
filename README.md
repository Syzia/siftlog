# Siftlog

A small SIEM for SSH auth logs and SSH honeypot logs. It parses logs into one event schema, stores them in SQLite, runs detection rules written in YAML, and serves the resulting alerts, with their evidence and an analyst workflow, over an HTTP API.

> **Status: MVP, with live detection.** The whole path works on simulated data: parse, store, locate, detect, score against ground truth, and serve, either as a one-off replay or continuously as a log file grows. It has a local dashboard for working through alerts. Logs from a Cowrie honeypot go through the same pipeline, with their own parser and rules; the honeypot rules have not been measured the way the SSH rules have.

```
 log file -> parser -> SQLite event store -> location enrichment -> rule engine -> alert store -> HTTP API -> dashboard
                |                                                       ^
           dead letters                                          rules/*.yml
```

The full design, including what changed while building it, is in [docs/architecture.md](docs/architecture.md). Findings, mistakes and the first real attack caught by the honeypot are in [docs/devlog.md](docs/devlog.md).

## Results

Measured over 50 independent simulations, each run through the real pipeline and scored against per-line ground truth:

| Rule | Expected | Detected | Alerts | False | Duplicate | Precision | Recall |
|------|---------:|---------:|-------:|------:|----------:|----------:|-------:|
| `ssh-brute-force` | 100 | 100 | 100 | 0 | 0 | 100.0% | 100.0% |
| `ssh-credential-stuffing` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| `ssh-impossible-travel` | 50 | 50 | 100 | 50 | 0 | 50.0% | 100.0% |
| `ssh-password-spray` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| `ssh-success-after-failures` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| **All** | 300 | 300 | 350 | 50 | 0 | 85.7% | 100.0% |

Attack scenarios: 300, detected 250 (83.3% of all attacks). Documented misses (attacks not expected to alert): 50.

The five rules raise **every alert they should, with no duplicates**. They are also wrong in two known, measured ways:

- **Precision is 85.7%.** Every false alert is the impossible-travel rule flagging a real user on a VPN. No speed threshold fixes it, because the VPN user and a thief both appear to teleport.
- **83.3% of all simulated attacks are detected.** A low-and-slow attack stays under every threshold.

These are simulated-data numbers and the thresholds were tuned against the simulator, so read them as a correctness check, not a performance claim. Definitions, known gaps, and sweeps showing where each rule breaks are in [docs/results.md](docs/results.md). A test regenerates these tables and fails if they drift from the code.

## Quick start

Needs Python 3.9 or newer. A local virtualenv keeps it tidy (`.venv/` is git-ignored):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install PyYAML fastapi uvicorn httpx pytest
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

# 4. run the rules, score the alerts against ground truth, and save them for the API
.venv/bin/python -m siftlog.engine --db siftlog.db --rules rules --labels sim.log.labels.json --log sim.log --save

# 5. open the dashboard. Starts the server and opens your browser, already signed in.
.venv/bin/python -m siftlog.api --db siftlog.db --rules rules --open
```

`--year` is required because classic syslog timestamps carry no year, and guessing would silently corrupt every timestamp.

**Live detection.** Instead of steps 2 to 4, one process can follow a log as it grows. New lines become events, and alerts are stored within a couple of seconds, where the API serves them:

```bash
.venv/bin/python -m siftlog.watch sim.log --db siftlog.db --rules rules --year 2026 --simulated-geo
```

It prints each alert as it opens and each time it grows. It survives log rotation, resumes where it stopped after a restart, and continues an attack already in progress as the same alert. Stop it with Ctrl+C.

**Honeypot data.** A [Cowrie](https://github.com/cowrie/cowrie) honeypot logs one JSON record per line. Those go through the same steps with `--source cowrie`, and need no `--year` because their timestamps are complete:

```bash
.venv/bin/python -m siftlog.ingest ~/honeypot-logs/cowrie.json* --source cowrie --db data/honeypot.db --show-ignored
.venv/bin/python -m siftlog.engine --db data/honeypot.db --rules rules --save
.venv/bin/python -m siftlog.api --db data/honeypot.db --rules rules --open
```

Besides logins, a honeypot records what a visitor did next, so there are three more event types: `connection`, `command` and `file_transfer`. `--show-ignored` lists what Cowrie logged that Siftlog does not turn into events. `--ignore-ip` leaves out your own address, so your test logins do not raise alerts about you. Keep real logs, and databases made from them, out of the repository: `data/` is git-ignored.

To reproduce the results tables: `.venv/bin/python -m siftlog.evaluate --published`.

## The dashboard

`python -m siftlog.api … --open` starts the server and opens `http://127.0.0.1:8000/dashboard/` in your browser. It is one page of plain HTML and JavaScript served by the API itself: no build step, nothing loaded from the internet.

- **Overview:** counts, alerts by rule and by day, events by type, and the busiest sources of failed logins, which is where a slow attacker shows up even when no rule fired.
- **Alerts:** filter, open one to see the log lines behind it, and acknowledge, close or reopen it with a note.
- **Events:** search stored events by address, username or type. A honeypot event shows the part that matters (the command typed, the password tried, the file and its hash) with the full log line as a tooltip.
- **Commands:** every command for running Siftlog and its honeypot, with this machine's own values filled in and a copy button. The same list, with placeholders, is in [docs/commands.md](docs/commands.md).

**Signing in.** The server prints a link ending in `#token=…` that opens the dashboard already signed in. The part after `#` never leaves your browser, and the page removes it from the address bar at once. The token is kept for that tab only.

**Your honeypot.** Put its address in a file named `siftlog.local.json` in the project folder, for example `{"honeypot_host": "192.0.2.10"}`. That file is git-ignored. The Overview then offers a *Check now* button that reports whether the honeypot and your admin login are answering, and the honeypot commands become ready to paste. Add `"own_addresses": ["203.0.113.5"]` with the address you connect from, and the command that loads honeypot logs leaves your own visits out.

## The API

Interactive documentation is at `http://127.0.0.1:8000/docs` once the server is running. Click **Authorize** and paste the token.

| Method | Path | What it does |
|--------|------|--------------|
| `GET` | `/health` | Liveness check. The only route that needs no token. |
| `GET` | `/alerts` | List alerts, newest activity first. Filter by `status`, `severity`, `rule_id`, `group_key`, `since`, `until`; page with `limit` and `offset`. |
| `GET` | `/alerts/{id}` | One alert with its evidence events and status history. |
| `PATCH` | `/alerts/{id}` | Record a decision: `{"status": "open" \| "ack" \| "closed", "note": "..."}`. |
| `GET` | `/events` | Search events by `src_ip`, `username`, `event_type` and time. |
| `GET` | `/stats` | Counts for a dashboard, including the busiest failing sources. |
| `GET` | `/rules` | Loaded rules and how many alerts each has raised. |

Every request except `/health` must send the token:

```bash
export SIFTLOG_API_TOKEN="a-long-random-value-you-chose"
.venv/bin/python -m siftlog.api --db siftlog.db --rules rules
```

```bash
curl -H "Authorization: Bearer $SIFTLOG_API_TOKEN" "http://127.0.0.1:8000/alerts?status=open"
```

If `SIFTLOG_API_TOKEN` is not set, a random token is generated for that run and printed once.

Two behaviours worth knowing:

- **Re-running the engine never erases a decision.** Detections are recomputed on each `--save`; statuses and notes are kept.
- **Closing means handled, not muted.** If a closed alert gains new activity, it is reopened automatically and the reason is recorded in its history.

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
- **A rule names the source it reads.** The `ssh-*` rules read `sshd` events and the `honeypot-*` rules read `cowrie` events. They are kept apart on purpose: on a honeypot nearly every login succeeds and every visitor is hostile, so a rule tuned for a real server would either stay silent or fire on everything.
- **Windows slide.** They end at the newest event, so an attack straddling a clock boundary is still caught.
- **One attack is one alert.** An alert stays open while its condition holds and closes after a cooldown (default: the timespan). A later burst opens a new one.
- **Validation is strict.** An unknown key is an error, so a typo stops the engine rather than producing a rule that never fires.

## Threat model

**Detects:** SSH brute force, password spraying, credential stuffing, a password guess that succeeded, and logins from impossibly distant places. On honeypot data: files brought onto the honeypot, commands run on it, and one address trying many accounts.

**Does not cover:**

- Anything that is not in the logs, and attackers who tamper with logs before they are ingested.
- Host-level malware, and attacks that never touch SSH authentication.
- Low-and-slow attacks under the thresholds, and brute forces spread across enough addresses to stay under them. Both are measured in [docs/results.md](docs/results.md).
- Users behind VPNs, who trip the travel rule. Location data is only as good as GeoIP.
- During live detection, events that arrive more than a couple of seconds out of order. They are stored, but the rules skip them until the watcher next starts and rebuilds from the store.

**How Siftlog protects itself.** Everything in a log line is attacker-controlled, so:

- **Parsing.** Patterns are anchored at the end of the line, so a username that looks like log syntax cannot spoof the source address. Honeypot records are JSON, read with the standard decoder: field types are checked, attacker-typed values are length-bounded, and nothing is taken from a field it does not belong to. Log content is never evaluated or passed to a shell. Lines are capped at 64 KiB, invalid UTF-8 is tolerated, and lines that do not parse are kept as dead letters instead of dropped.
- **Storage.** Every query is parameterised, and column names never come from input.
- **Rules.** Loaded with `yaml.safe_load`, so a rule file cannot construct Python objects.
- **Engine.** Evidence is capped per alert, idle state is dropped, and each rule tracks a capped number of groups, forgetting the least recently active first. One attacker cycling through usernames cannot grow memory without bound.
- **API.** A bearer token on every route but `/health`, compared in constant time. It listens on this machine only by default and refuses to listen elsewhere with a generated token. Parameters are typed and bounded. Responses are JSON only.
- **Dashboard.** Log content is only ever inserted into the page as text, never as markup. A strict content security policy backs that up: no inline script, nothing from another origin, no framing. The honeypot check only ever connects to the address in your local settings file, and only when you click.
- **Repository.** No real logs, credentials or attack traffic. Fixtures use documentation address ranges. Machine-specific values such as the honeypot's address live in a git-ignored file.

**Known weaknesses.** One shared token and no user accounts, so the history records the actor as `api`. The sign-in link contains that token, so treat the terminal it was printed in accordingly. No TLS: beyond this machine it needs a reverse proxy. No rate limiting. The database is a single file, and anyone who can read it can read everything. Usernames and raw lines are returned as data, so anything that displays them must escape them.

## Build stages

| Stage | Deliverable | Status |
|-------|-------------|--------|
| 0 | Cowrie honeypot on an isolated VPS ([runbook](docs/honeypot.md)) | deployed 2026-10-13 |
| 1 | Labelled log simulator + SSH parser + event schema | done |
| 2 | SQLite event store + idempotent batch ingest | done |
| 3 | Replay-mode engine, `event_count` and `value_count` rules | done |
| 4 | `temporal_ordered` + `impossible_travel` rules, GeoIP enrichment | done |
| 5 | Alert store with analyst workflow + HTTP API (**MVP**) | done |
| 6 | Live detection: streaming engine + log follower | done |
| 7 | Local dashboard (plain HTML and JavaScript, no build step) | done |
| 8 | Honeypot data: Cowrie parser, three honeypot rules, own-address filter | done |
| 9 | Sigma rule import (stretch) | not started |

The original plan also had a web log parser in stage 8. It was left out: the honeypot is SSH-only, so there is no real web data to build it against.

## Safety

This project handles attacker-controlled input. Only run it against logs from systems you own or have permission to monitor. No real logs, credentials or attack traffic belong in this repository.
