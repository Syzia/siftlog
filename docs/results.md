# Detection results

How well the shipped rules detect the simulated attacks, measured rather than asserted.

**Read this first:** these numbers come from *simulated* traffic, and the thresholds were chosen by someone who had seen the simulator. Perfect scores on the implemented rules are therefore expected, and are not evidence about real attackers. The informative parts are the gaps, the definition of a false alert, and the threshold sweeps further down. Real data arrives at stage 8.

## How it is measured

- **50 independent simulations** (seeds 1 to 50), 31,196 events in total. Each one contains five attack scenarios and four benign ones, at random times, so timing and overlaps vary between runs.
- Each simulation goes through the **real pipeline**: generated log lines, the sshd parser, the SQLite event store, then the replay engine with the rules in `rules/`.
- The simulator labels **every line** with the scenario that produced it, so each alert is judged on its own evidence.

Definitions:

- **Recall** is per scenario: of the scenarios a rule should catch, how many did it raise an alert for?
- **Precision** is per alert: the share of alerts that are *not false*.
- A **false** alert is one whose evidence is mostly benign traffic.
- A **duplicate** is a second alert for an attack the rule already reported. It is real, but it is noise, and it is counted separately from false alerts.
- A **bonus** is the first alert on a real attack the rule was not expected to catch. It counts as correct.

## Results at the shipped thresholds

| Rule | Expected | Detected | Alerts | False | Duplicate | Precision | Recall |
|------|---------:|---------:|-------:|------:|----------:|----------:|-------:|
| `ssh-brute-force` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| `ssh-credential-stuffing` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| `ssh-impossible-travel` *(not implemented)* | 50 | 0 | 0 | 0 | 0 | n/a | 0.0% |
| `ssh-password-spray` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| **All** | 200 | 150 | 150 | 0 | 0 | 100.0% | 75.0% |

Attack scenarios: 250, detected 150 (60.0% of all attacks). Documented misses (attacks not expected to alert): 50.

What this says:

- The three implemented rules each raised **exactly one alert per attack** and nothing on benign traffic, in all 50 runs.
- **Overall recall is 75%, not 100%**, because impossible travel has no rule yet (stage 4). It is shown as a row with zero detections rather than left out.
- **60% of all attacks are detected.** The difference from 75% is the low-and-slow scenario: one failure every two and a half minutes for six hours. It is a real attack that stays under every threshold here, and it is labelled as a documented miss so it cannot be quietly forgotten.

## Threshold sweeps

One rule's threshold is varied while the others stay as shipped. This is what shows the scoring can tell a good threshold from a bad one.

### Brute force: failures from one address in 5 minutes

| `ssh-brute-force` threshold | Detected | Alerts | False | Duplicate | Bonus | Precision | Recall |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 | 50 / 50 | 1519 | 104 | 1215 | 150 | 93.2% | 100.0% |
| 5 | 50 / 50 | 151 | 51 | 0 | 50 | 66.2% | 100.0% |
| 10 (shipped) | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 20 | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 40 | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 45 | 0 / 50 | 0 | 0 | 0 | 0 | n/a | 0.0% |

- **Too low (5):** recall holds, but the once-a-minute monitoring probe trips it in every run. Those are the false alerts. It also catches the password sprayer, which is the bonus column.
- **At an attacker's own rate (3):** the low-and-slow attacker hovers around three failures per five minutes, so the condition keeps lapsing and re-firing: one attack becomes about 19 alerts per run. Each stuffing address that tried three passwords also raises its own alert, about 8 per run. Both land in the duplicate column. A threshold sitting on top of an attacker's rate produces alert flapping, not detection.
- **Too high (45):** the simulated brute force is 40 attempts, so it is missed entirely.
- Anything from 10 to 40 behaves identically here, which is a property of the simulator, not a finding. Real attackers will not leave that much room.

### Password spray: distinct usernames from one address in 10 minutes

| `ssh-password-spray` threshold | Detected | Alerts | False | Duplicate | Bonus | Precision | Recall |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 | 50 / 50 | 562 | 58 | 354 | 100 | 89.7% | 100.0% |
| 6 | 50 / 50 | 51 | 1 | 0 | 0 | 98.0% | 100.0% |
| 8 (shipped) | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 12 | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 31 | 0 / 50 | 0 | 0 | 0 | 0 | n/a | 0.0% |

- At 6, one run produces a false alert: the NAT'd office, where six different people mistyped a password inside ten minutes. That is the realistic failure mode for this rule, and the reason the threshold is not lower.

### Credential stuffing: distinct addresses failing against one host in 10 minutes

| `ssh-credential-stuffing` threshold | Detected | Alerts | False | Duplicate | Bonus | Precision | Recall |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 | 50 / 50 | 57 | 4 | 0 | 3 | 93.0% | 100.0% |
| 7 | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 15 (shipped) | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 25 | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 26 | 17 / 50 | 17 | 0 | 0 | 0 | 100.0% | 34.0% |

- At 26 the rule only fires when unrelated failures happen to overlap the 25-address attack, which is why recall collapses to a third rather than to zero.

## Known gaps

- **Impossible travel** is not implemented (stage 4).
- **Low-and-slow** attacks are missed by design at these thresholds. Catching them needs a longer window or a different signal, not a lower threshold (see the sweep above).
- **Address rotation.** An attacker spreading a brute force across many addresses stays under the per-address rule. The stuffing rule covers the many-addresses-one-host shape, but only above 15 sources in ten minutes.
- **Simulated data only.** The simulator's traffic is cleaner and more regular than real logs. Expect these numbers to drop on the honeypot data.

## Reproduce

```bash
python -m siftlog.evaluate --published
```

A test (`tests/test_results_doc.py`) regenerates every table on this page and fails if the page is out of date.
