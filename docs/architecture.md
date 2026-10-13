# SIEM Architecture

Working name: **Siftlog** (rename freely; avoid anything that sounds like an existing SIEM product).

## Design Principles
- **Simulated before live.** A log generator comes first, so every detection rule is tested against known-good and known-bad traffic before touching real logs.
- **Ground truth everywhere.** The simulator labels every event with the scenario that produced it (`brute_force`, `typo_benign`, ...). Without labels, "it works" can't be measured.
- **Simplest thing that works.** SQLite, one FastAPI process, no Kafka, no Elasticsearch. Swap components only when we hit a real limit.
- **Rules are data, not code.** Detections live in YAML files, so adding a rule never requires touching the engine.

## High-Level Data Flow

```
 ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌───────────────┐
 │  Log Source │──▶│   Ingestor   │──▶│  Normalizer  │──▶│ Event Store   │
 │ (sim / real)│   │ (tail/batch) │   │ (parsers)    │   │ (SQLite)      │
 └─────────────┘   └──────────────┘   └──────────────┘   └───────┬───────┘
                                                                  │
                                                                  ▼
 ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌───────────────┐
 │  Dashboard  │◀──│   REST API   │◀──│ Alert Store  │◀──│ Detection     │
 │  (React)    │   │  (FastAPI)   │   │ (SQLite)     │   │ Engine        │
 └─────────────┘   └──────────────┘   └──────────────┘   └───────▲───────┘
                                                                  │
                                                          ┌───────┴───────┐
                                                          │ Rules (YAML)  │
                                                          └───────────────┘
```

## Components

### 1. Log Sources
- **Simulator (build first):** generates realistic SSH auth logs and web access logs with configurable scenarios, each emitting a ground-truth label file alongside the log. Seeded RNG so tests are reproducible.
  - *Attacks:* brute force, password spraying, credential stuffing, impossible travel, low-and-slow (deliberately under threshold, to document what the rules miss).
  - *Benign noise:* fat-fingered passwords, a NAT'd office IP where many real users log in, a user travelling legitimately, a monitoring probe that fails every minute.
- **Real fixtures (stage 1):** a few dozen *real* sshd lines, sanitized, checked into `tests/fixtures/`. Parsing logs you generated yourself only proves the parser agrees with the generator.
- **Real sources (later):** `/var/log/auth.log`, nginx/Apache access logs, Cowrie JSON output (project #2).
  - Debian 12+ has no `/var/log/auth.log` by default (journald only). Install rsyslog or ingest `journalctl -o json`.

### 2. Ingestor
- Two modes: **batch** (read a file once, used in tests) and **tail** (follow a file live, surviving rotation).
- Hands raw lines to the normalizer. No parsing logic here.
- Ingest is **idempotent**: re-reading a file must not double-count events (see event ids below).

As built (stage 2):
- **Stream identity** is a hash of the file's *first line*, not its path. Rotation renames `auth.log` to `auth.log.1` and gzips it later; the same events must not be counted again. A first line carries a timestamp, so it differs between rotations but stays stable while the file grows. Pass an explicit `source_id` when two streams could share a first line.
- `.gz` files are read transparently, and offsets are *uncompressed* offsets, so a compressed copy yields the same event ids.
- A **final line with no trailing newline is left alone** (and reported): it may still be being written, and ids are offset-based, so storing a truncated version would be permanent. The next ingest picks it up once complete.
- **Lines are capped at 64 KiB.** Logs carry attacker-controlled bytes; an overlong line is truncated (so it dead-letters) and the rest is skipped without being held in memory, with later offsets unaffected.
- Writes commit per chunk, so an interrupted ingest is simply run again.

### 3. Normalizer (parsers)
Converts every log format into one common event schema. One parser per source, registered by name.

```python
@dataclass
class Event:
    id: str                 # deterministic: hash(file identity, byte offset)
    timestamp: datetime     # always UTC
    source: str             # "sshd", "nginx", "cowrie", ...
    event_type: str         # "auth_failure", "auth_success", "http_request"
    src_ip: str | None
    username: str | None
    host: str | None
    outcome: str | None     # "success" | "failure"
    count: int              # 1 normally; N for "message repeated N times"
    geo: dict | None        # country/lat/lon, filled by enrichment
    extra: dict             # source-specific: http method/path/status/user_agent, ssh auth method, port
    raw: str                # original line, for audit and debugging
    source_id: str          # which stream the line came from (see "Stream identity")
    offset: int             # byte offset of the line in that stream
```

Things that will bite you in the parsers:
- **Timestamps.** Classic syslog lines (`Oct 13 11:16:02`) carry no year and no timezone. The parser takes the host timezone and a reference year as config, and detects the December-to-January rollover when time appears to go backwards. Prefer ISO 8601 sources (rsyslog high-precision format, journald JSON) when you have a choice.
- **Collapsed lines.** `message repeated 5 times: [ Failed password for ... ]` is one line carrying five events. Carry that in `count` or the engine undercounts exactly during the attacks you care about.
- **Attacker-controlled fields.** A username can contain spaces and text that looks like the rest of the line (`admin from 1.2.3.4 port 22`). Anchor patterns and take the IP from its structural position, never the first thing that looks like one.
- **Deterministic ids.** Don't hash the raw line alone, since two identical failures in the same second are two events. Hash file identity plus byte offset.

Unparseable lines go to a dead-letter table instead of being dropped. Parsers are where real-world messiness lives, so this makes failures visible.

As built (stage 8), the Cowrie honeypot parser:
- **Three more event types**, `connection`, `command` and `file_transfer`, for what a visitor does besides logging in. Only a honeypot produces them. Source-specific detail (the command, the password tried, the file's name, URL and hash, Cowrie's session id) goes in `extra`.
- **Most of what Cowrie logs is ignored, with a reason.** It writes many event types, and session bookkeeping and client fingerprints are not attacker actions. Each ignored line is counted under its `eventid`, and `--show-ignored` prints the counts, so the decision about what to keep can be revisited with numbers. An `eventid` Cowrie adds in a future version is ignored the same way, not treated as an error.
- **A dead letter means "Cowrie would not have written this"**: not JSON, no event id, no usable timestamp, or no source address on an event that needs one.
- **`cowrie.command.failed` is ignored on purpose.** Cowrie logs `command.input` for every line typed and then `command.failed` if the command was not found. Counting both would double it.
- **The injection risk is different from sshd's.** In free text a username can impersonate the rest of the line. In JSON it cannot, so the care goes into types instead: a field that is not a string is treated as absent, the source address must be an address *in a string* (`ip_address(5)` is valid Python), and attacker-typed values are cut to 4,096 characters in structured fields while `raw` keeps the whole line.
- **No year is needed.** Cowrie timestamps are complete, so `--year` is required only for sources that need it. A parser declares which with `needs_year`.
- **Your own visits can be left out.** `--ignore-ip` drops lines from the addresses you name, counted as ignored (`own-address`). It is done at ingest, so those events are never stored. Adding an address later means rebuilding the database.
- **A `file_download` with no URL is a file a shell command wrote**, not something fetched. Real data showed this on its first day: 16 of 17 file events. They get `direction: written` and keep `destfile`.
- **Re-parsing means rebuilding.** Event ids are deterministic and inserts skip what is already stored, which is what makes ingest safe to repeat. The cost: when a parser starts extracting a field differently, events already stored keep the old version until the database is rebuilt, and analyst decisions on its alerts go with it.
- **Known gap:** a record longer than the 64 KiB line cap is cut short, stops being valid JSON, and becomes a dead letter. A very long pasted command is exactly the kind of record this could lose as an event. It is still kept, truncated, in the dead-letter table.

### 4. Enrichment (optional step in the normalizer)
GeoIP lookup via the offline MaxMind GeoLite2 database (no API calls, no rate limits). Required for impossible-travel detection.
- Needs a free MaxMind account and licence key, and the database can't be redistributed. Keep it out of the repo and document how to fetch it.
- CI and tests use a small fake lookup table (IP to coordinates) so they never depend on the real database.

As built (stage 4):
- **A resolver is anything with `lookup(ip)`.** `TableGeoResolver` serves the simulator's table; `MaxMindGeoResolver` adapts a GeoLite2-City reader. The reader is injected, so the record mapping is tested without the database. Opening a real `.mmdb` needs the optional `maxminddb` package and is the one line not exercised in CI.
- **Enrichment is a separate pass over the store**, `python -m siftlog.enrich`, not part of ingest. A GeoIP database often arrives after the logs do, and re-ingesting cannot add a location because stored rows are never rewritten. The pass only touches events with no location, so it is safe to repeat.
- **Events that cannot be located are left alone**, and are invisible to location rules.

### 5. Event Store
SQLite with indexes on `(src_ip, timestamp)` and `(username, timestamp)`, since nearly every rule is a windowed query on those. Move to Postgres only if write volume or concurrency becomes a real problem.

As built (stage 2):
- `events.id` is `UNIQUE` and inserts are `OR IGNORE`, so writes are idempotent.
- Timestamps are **integer microseconds since the epoch (UTC)**: exact, and range queries are integer comparisons. `since` is inclusive and `until` exclusive, so adjacent windows never overlap.
- Results are ordered by `(timestamp, source_id, byte_offset)`: time first, then file order. Syslog has one-second resolution, so ties are common and "failures then success" rules need a meaningful order within a second.
- A third index on `(timestamp)` serves replay mode, which scans a time range regardless of who. There is deliberately no `(event_type, timestamp)` index yet; add it with a schema-version bump when a rule's plan shows it is needed.
- `PRAGMA user_version` holds the schema version. A newer or unknown database is refused rather than guessed at.
- Every query is parameterised. Usernames are attacker-controlled log content, so values never reach the SQL text.
- `count(weighted=True)` sums `repeat_count`; rules that threshold on attempts must use it, because one row can stand for several events.
- Dead letters live in their own table, keyed by `(source_id, byte_offset)`, so they are idempotent too.

### 6. Detection Engine
Rule types are named after Sigma's correlation types (`event_count`, `value_count`, `temporal`), so the stage 9 Sigma import is mostly field mapping rather than a redesign. `impossible_travel` is a custom extension.

| Type | Meaning | Detects |
|------|---------|---------|
| `event_count` | N matching events within a window, per group | brute force |
| `value_count` | N *distinct* values of a field within a window, per group | password spraying, credential stuffing |
| `temporal_ordered` | Step A then step B, in order, for the same group within a window | failures streak then success |
| `impossible_travel` | Two successes for one user too far apart for the elapsed time | stolen credentials |

Example rules:

```yaml
id: ssh-brute-force
title: SSH brute force
severity: high
type: event_count
filter:
  event_type: auth_failure
  source: sshd
group_by: [src_ip]
timespan: 5m
condition:
  gte: 10
mitre: [T1110.001]
```

```yaml
id: ssh-password-spray
title: SSH password spraying
severity: high
type: value_count
filter:
  event_type: auth_failure
  source: sshd
group_by: [src_ip]
distinct: username
timespan: 10m
condition:
  gte: 8
mitre: [T1110.003]
```

Notes on the rule semantics:
- **Passwords aren't in the logs**, so spraying and stuffing are told apart by shape. Spraying is one IP hitting many accounts. Stuffing is usually many IPs hitting one endpoint, each account tried about once, with a high failure ratio. A stuffing rule therefore groups by `host` or endpoint and counts distinct `src_ip`, not the other way round.
- **Sliding windows, not fixed buckets.** Fixed windows miss an attack that straddles a boundary (9 failures at 4:59 and 9 at 5:01 never reach a threshold of 10).
- **`count` matters.** Count events with `sum(count)`, not row count.

Engine runs in **streaming mode** (evaluate each new event against the state it needs) and **replay mode** (run all rules over a stored time range, used for tests and backtesting). Build replay first, since it's deterministic and easy to test. Replay sorts by event timestamp. Streaming has to tolerate slightly out-of-order arrival, so decide on an allowed lateness up front.

**Alerts are episodes, not windows.** When a rule's condition first becomes true for a group key, open an alert. Each new event that arrives **while the condition still holds** extends `last_seen` and `event_count`. Once the condition has not held for `cooldown` (default: the rule's `timespan`), the episode ends and a later burst opens a new alert.

> **Corrected during stage 3.** The first draft said "while matching events keep arriving". That is wrong for any rule grouped by host: an internet-facing host always has auth failures, so the first stuffing alert would never close and would swallow every later attack. The episode has to follow the condition, not the event stream. A regression test covers it. There is at most one open alert per `(rule_id, group_key)`, so one attack produces one alert, not 500. Closing an alert means "handled", not "muted": if the attack is still running, the next match opens a fresh one.

As built (stage 3):
- **Replay engine** (`siftlog/engine/replay.py`) with `event_count` and `value_count`. The other two types arrived in stage 4 (below).
- **The window is `(t - timespan, t]`**, ending at the newest event. An event exactly one timespan old is outside it.
- **`first_seen` is the earliest event in the window that triggered the alert**, and the evidence is that whole window plus everything that arrives while the condition holds. For a host-level rule this can predate the attack by up to one timespan.
- **Evidence ids are capped at 1,000 per alert** (`evidence_truncated` says when). Counts stay exact. This bounds what one attacker can make a single alert hold.
- **Idle groups are dropped** as replay proceeds, so memory follows the number of active groups rather than every key ever seen. A test checks this never changes the result.
- **Rule files are validated strictly and loaded with `yaml.safe_load`.** An unknown key is an error, so a typo such as `treshold` stops the engine instead of producing a rule that never fires.
- **Alert ids are deterministic:** a hash of rule id, group key and `first_seen`.
- **Scoring** (`siftlog/engine/scoring.py`) judges each alert on its own evidence, using the simulator's per-line labels: an alert is *false* only if most of its evidence is benign. Duplicates and "bonus" detections of unexpected attacks are counted separately. Measured results are in [results.md](results.md).

As built (stage 4):
- **`temporal_ordered`**, not plain `temporal`: Sigma's `temporal` is unordered, and "failures then success" needs order. A rule lists `steps`, each a filter and a count; an event counts towards one step only.
- **Only an event that completes the sequence opens or extends an alert.** A stray failure after the successful login is not evidence. This also keeps a huge brute force from rescanning its window on every failure.
- **`ssh-success-after-failures` groups by address *and* username.** Grouped by address alone it fires on a NAT'd office where several people mistype and somebody else logs in. Measured in [results.md](results.md).
- **`impossible_travel`** compares each located login with the previous located login for the same user: flagged if they are at least `min_distance_km` apart and the implied speed exceeds `max_speed_kmh`. The minimum distance absorbs GeoIP jitter between neighbouring networks. The alert's `summary` gives places, distance and speed.
- **One attack may expect several alerts.** A brute force that succeeds should trip both `ssh-brute-force` and `ssh-success-after-failures`, so labels carry a list of expected (rule, group key) pairs and recall is counted per expected alert.
- **A documented false positive.** The simulator now contains a real user on a VPN, which the travel rule flags. It is the mirror image of the low-and-slow documented miss: a known wrong answer kept visible in the results instead of a flattering zero.

As built (stage 6, live detection):
- **One evaluator, two drivers.** Streaming (`siftlog/engine/stream.py`) feeds the same evaluators as replay, a few events at a time. A test checks that feeding a simulation in any chunking ends in exactly the alerts a replay produces.
- **Alerts are reported while open.** Replay reports an alert when its episode ends. Streaming reads open alerts as they stand after each batch. The id is fixed when the episode opens, so each newer version updates the same stored alert.
- **Allowed lateness is two seconds by default.** Each event is held that long after it arrives, then released in timestamp order. An event later than that is still stored, but skipped by detection and counted. It is picked up the next time state is rebuilt.
- **Starting up rebuilds from the whole store**, then reconciles the alert table as a full replay would. A restart mid-attack therefore continues the same alert, with the same id and any analyst decision intact, and repairs whatever was missed while the process was down. The cost is one pass over every stored event at startup, which is fine at SQLite scale and is the first thing to change beyond it.
- **State is capped.** Each rule tracks at most 200,000 groups and forgets the least recently active first; an evicted group's open alert is closed, not lost. The cap is a trade-off (an attacker pushed out mid-count is forgotten), and the engine counts evictions so it is visible.
- **The log follower** (`siftlog/ingest/tail.py`) behaves like `tail -F`: it waits for a half-written line, reads a renamed file to its end before moving to the new one, and treats truncation or an in-place rewrite as a new stream. Its offsets and stream identities match the batch reader's, so a line gets the same event id either way.
- **Checkpoints** (schema version 3) record how far each stream has been read, plus the parser's year, so a restart neither re-reads nor forgets that the log has passed New Year. A file rotated in continues the year the old one had reached.
- **A stop signal is handled like Ctrl+C**, so events still in the ordering buffer are evaluated before the process exits.
- **Known limits.** Ties between two different files within the same second can be ordered differently from a replay. A new stream whose first line is identical to an old one's is treated as that stream.

### 7. Alert Store
```
alerts(id, rule_id, severity, group_key, first_seen, last_seen,
       event_count, status[open|ack|closed])
alert_events(alert_id, event_id)      -- evidence, one row per event
```
Every alert links back to its evidence events. Analysts need to see why it fired.

As built (stage 5):
- **Detections are recomputed; decisions persist.** Replay is deterministic and alert ids are a hash of rule, group and `first_seen`, so re-running the engine reproduces the same alerts. `python -m siftlog.engine --save` makes the table match the latest full replay and never touches `status` or `note`.
- **Closing means handled, not muted.** The one exception to the rule above: a *closed* alert that has gained activity since is reopened, by the actor `siftlog`, with the reason recorded. An acknowledged alert that grows stays acknowledged.
- **Nothing an analyst touched is silently deleted.** If a rule edit means the latest replay no longer produces an alert, it is removed only if nobody acted on it. Otherwise it is kept and marked `superseded`, hidden from listings by default.
- **`alert_history`** records every status change: when, from, to, by whom, and why. The API writes the actor `api`, because there is one shared token and no user accounts yet.
- **`--save` requires a full replay.** A partial time range cannot tell "no longer produced" from "outside the range".
- **Schema version 2.** A stage 4 database is upgraded in place, in one transaction, on first open.
- Evidence is a join table with a position, so it comes back in the order the engine recorded it. Evidence events that have since been deleted are skipped rather than breaking the alert.

### 8. REST API (FastAPI)
- `GET /alerts`, `GET /alerts/{id}` (with evidence)
- `PATCH /alerts/{id}` (change status)
- `GET /events?src_ip=&since=`
- `GET /stats` (top IPs, alerts over time, by severity)
- `GET /rules` (loaded rules and their hit counts)

As built (stage 5):
- **Every route except `GET /health` needs `Authorization: Bearer <token>`**, compared in constant time. The token comes from `SIFTLOG_API_TOKEN`; without it, one is generated for the run and printed once.
- **Loopback by default.** The CLI refuses to bind anywhere else with a generated token, and warns that it speaks plain HTTP. TLS belongs to a reverse proxy.
- **Inputs are typed and bounded:** page sizes from 1 to 1000, string lengths capped, statuses and severities are enumerations, unknown fields in a `PATCH` body are rejected. A timestamp with no offset is read as UTC.
- **One SQLite connection per request, opened inside the handler.** FastAPI runs plain handlers in a thread pool, and a connection must not cross threads.
- **JSON only**, with `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. Usernames and raw lines are attacker-controlled text returned as data; whatever renders them must escape them.
- `GET /alerts/{id}` returns the alert, its evidence events (200 by default, up to 1000) and its history. `GET /stats` includes the busiest failing sources, which is how the low-and-slow attacker shows up even though no rule fires on it.
- Interactive documentation is served at `/docs`, with the bearer scheme declared so its Authorize button works.
- **Not built:** user accounts or roles, rate limiting, TLS, CORS for a browser front end (stage 7 will need it).

### 9. Dashboard (React, optional)
- Alert queue with severity filter and status workflow
- Alert detail view showing evidence events
- Top attacker IPs, alerts over time, geo map
- Keep it minimal. The detection logic is the point, not the UI polish. This is the most effort for the least signal in a detection role, so it comes after the MVP.

As built (stage 7):
- **Plain HTML, CSS and one JavaScript file, not React.** No build step, no package manager, and nothing fetched from the internet. The files are served by the API from `siftlog/api/static/`.
- **Data is inserted as text only.** Usernames and raw lines are attacker-controlled, so the script builds every element with one helper that creates text nodes. A test fails if the script ever uses a markup-parsing or code-evaluating API. A strict content security policy (no inline script, same origin only, no framing) is the second line of defence.
- **Sign-in is a link, not a form.** The server prints a URL whose fragment carries the token. A fragment is never sent to a server or written to a request log. The page stores it for the tab and removes it from the address bar. A token the operator chose is never printed.
- **The command reference is data.** `static/commands.json` holds every command with `{{name}}` placeholders. The dashboard fills in this machine's values; `docs/commands.md` is generated from the same file with neutral placeholders, and a test keeps the two in step.
- **Machine-specific values stay out of git.** The honeypot's address and key path come from `siftlog.local.json`. Every value is validated before it is put into a command, because these are commands a person will paste into a shell.
- **The honeypot check is on demand.** It connects to the two ports of the configured host and reports what each says it is. The target cannot be chosen by a request. It runs only on a click and is cached for a minute, because each check is a visit the honeypot records.
- The original plan's geo map is not built.

## Repo Layout

```
siftlog/
├── README.md
├── docs/                  # architecture diagram, threat model, results table
├── siftlog/
│   ├── simulator/         # attack + benign scenario generators, label files
│   ├── ingest/
│   ├── parsers/           # one module per log format
│   ├── enrich/
│   ├── store/
│   ├── engine/            # event_count, value_count, temporal, travel evaluators
│   └── api/
├── rules/                 # YAML detections
├── tests/
│   ├── fixtures/          # sanitized real sample logs
│   └── scenarios/         # simulator-driven end-to-end tests with labels
├── dashboard/             # React app
├── docker-compose.yml
└── .github/workflows/ci.yml
```

## Build Stages (each one testable on its own)

Stage 0 runs in parallel with everything else. Stage 5 is the MVP: write the README, threat model and results table there, and treat everything after as improvement.

| Stage | Deliverable | How you know it works |
|-------|-------------|-----------------------|
| 0 | Cowrie honeypot on an isolated VPS, raw logs accumulating outside the repo | Log file is growing; nothing personal on the box |
| 1 | Labelled log simulator + SSH parser + event schema | Generated logs parse into events with 0 dead-letters, and the real-line fixture file parses too |
| 2 | SQLite event store + idempotent batch ingest | Ingest 100k simulated events; re-ingesting the same file changes nothing; query by IP/time |
| 3 | Replay-mode engine with `event_count` and `value_count` rules | Per-rule precision/recall computed against the labels: each attack scenario fires exactly 1 alert, benign and noisy-benign scenarios fire 0 |
| 4 | `temporal` + `impossible_travel` rules + GeoIP enrichment | Impossible-travel and "failures then success" scenarios fire correctly, legitimate travel doesn't |
| 5 | FastAPI + episode-based alerts + status workflow (**MVP**) | API tests cover every endpoint; README, threat model and results table written |
| 6 | Streaming mode + tail ingestor | Append to a log file, alert appears in seconds |
| 7 | React dashboard (optional) | Demo GIF for the README |
| 8 | Real data (Cowrie output + own server) + web log parser | Run against live logs, tune false positives, add the findings to the README |

As built, stage 8 is the Cowrie parser, three honeypot rules and the own-address filter. The web log parser was left out because the honeypot is SSH-only, so there is no real web data to build one against. The rules were written from the shape of the first day's traffic and have not been tuned against a longer run.
| 9 (stretch) | Sigma rule import | Load a public Sigma rule and have it fire |

Stage 3 is the milestone that matters. A deterministic precision/recall test against *labelled* simulated attacks, including noisy benign traffic and a documented low-and-slow miss, is the strongest thing you can show in an interview.

## Threat Model (put a version of this in the README)

**Protects against / detects:** brute force, password spraying, credential stuffing, anomalous geo-logins, suspicious request patterns.

**Does not cover:** encrypted or in-memory attacks, anything not logged, attackers who tamper with logs before ingestion, host-level malware, low-and-slow attacks under the configured thresholds, attackers rotating through enough IPs to stay under per-IP thresholds.

**Own-security notes:**
- Parsers handle untrusted input. Fuzz them, and never `eval` or shell out on log content.
- Log injection: attackers control fields like usernames. Escape on render in the dashboard (XSS) and use parameterized SQL everywhere.
- Resource exhaustion: streaming window state is keyed by attacker-controlled values (`src_ip`, `username`). Cap the number of tracked groups and evict the oldest, or one scanner cycling random usernames exhausts memory.
- API needs auth before it leaves localhost.
- Never commit real logs. Sanitize IPs and usernames in fixtures.

## Decisions to Defend in Interviews
- **SQLite over Elasticsearch/Kafka:** volume doesn't justify the operational cost; the schema and rules are the interesting part. Know the point at which you'd migrate.
- **YAML rules over hard-coded detections:** separates detection content from the engine, same model as real SIEMs.
- **Sigma-shaped rule types:** the rule format mirrors an industry standard, so detection content is portable instead of locked to this engine.
- **Replay mode first:** deterministic backtesting makes rules testable and tunable, which is how detection engineering works in practice.
- **Sliding windows and alert episodes:** fixed buckets miss boundary-straddling attacks, and per-window dedup produces either duplicate alerts or silent gaps.
- **Labelled simulator:** precision and recall are only meaningful with ground truth, and the known misses are part of the result.
- **Dead-letter table:** parse failures are visible instead of silently lost.
