# Detection results

How well the shipped rules detect the simulated attacks, measured rather than asserted.

**Read this first:** these numbers come from *simulated* traffic, and the thresholds were chosen by someone who had seen the simulator. High scores are therefore expected, and are not evidence about real attackers. The informative parts are the two things the rules are known to get wrong, the definition of a false alert, and the sweeps further down that show where each rule breaks.

Only the five `ssh-*` rules are measured here. The five `honeypot-*` rules read honeypot events, which the simulator does not produce, so they are left out of every table rather than shown as rows of zeros. They have tests, but no precision or recall figures: a honeypot log has no ground truth to score against.

## How it is measured

- **50 independent simulations** (seeds 1 to 50), 32,596 events in total. Each one contains six attack scenarios and five benign ones, at random times, so timing and overlaps vary between runs.
- Each simulation goes through the **real pipeline**: generated log lines, the sshd parser, location enrichment, the SQLite event store, then the replay engine with the rules in `rules/`.
- The simulator labels **every line** with the scenario that produced it, so each alert is judged on its own evidence.

Definitions:

- **Recall** is per expected alert: of the alerts a rule should raise, how many did it raise? One attack can expect more than one. A brute force that succeeds should trip both the brute-force rule and the success-after-failures rule, which is why `ssh-brute-force` expects 100 below.
- **Precision** is per alert: the share of alerts that are *not false*.
- A **false** alert is one whose evidence is mostly benign traffic.
- A **duplicate** is a second alert for an attack the rule already reported. It is real, but it is noise, and it is counted separately from false alerts.
- A **bonus** is the first alert on a real attack the rule was not expected to catch. It counts as correct.

## Results at the shipped settings

| Rule | Expected | Detected | Alerts | False | Duplicate | Precision | Recall |
|------|---------:|---------:|-------:|------:|----------:|----------:|-------:|
| `ssh-brute-force` | 100 | 100 | 100 | 0 | 0 | 100.0% | 100.0% |
| `ssh-credential-stuffing` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| `ssh-impossible-travel` | 50 | 50 | 100 | 50 | 0 | 50.0% | 100.0% |
| `ssh-password-spray` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| `ssh-success-after-failures` | 50 | 50 | 50 | 0 | 0 | 100.0% | 100.0% |
| **All** | 300 | 300 | 350 | 50 | 0 | 85.7% | 100.0% |

Attack scenarios: 300, detected 250 (83.3% of all attacks). Documented misses (attacks not expected to alert): 50.

What this says:

- **Every expected alert was raised**, in all 50 runs, with no duplicates.
- **Precision is 85.7%, not 100%.** All 50 false alerts are the same thing: `ssh-impossible-travel` firing on a real user who logged in from London and then, ten minutes later, through a VPN exit in New York. By location alone that is indistinguishable from stolen credentials. It is in the simulator on purpose, as a documented false positive, and the sweep below shows why no setting fixes it.
- **83.3% of all attacks are detected, not 100%.** The gap is the low-and-slow scenario: one failure every two and a half minutes for six hours. It is a real attack that stays under every threshold here, labelled as a documented miss so it cannot be quietly forgotten.

So the rules are known to be wrong in two specific ways: one benign thing they flag, and one attack they miss.

## Sweeps

One rule's main setting is varied while the others stay as shipped. This is what shows the scoring can tell a good setting from a bad one.

### Brute force: failures from one address in 5 minutes

| `ssh-brute-force` threshold | Detected | Alerts | False | Duplicate | Bonus | Precision | Recall |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 | 100 / 100 | 1569 | 104 | 1215 | 150 | 93.4% | 100.0% |
| 5 | 100 / 100 | 201 | 51 | 0 | 50 | 74.6% | 100.0% |
| 10 (shipped) | 100 / 100 | 100 | 0 | 0 | 0 | 100.0% | 100.0% |
| 20 | 100 / 100 | 100 | 0 | 0 | 0 | 100.0% | 100.0% |
| 26 | 50 / 100 | 50 | 0 | 0 | 0 | 100.0% | 50.0% |
| 45 | 0 / 100 | 0 | 0 | 0 | 0 | n/a | 0.0% |

- **Too low (5):** recall holds, but the once-a-minute monitoring probe trips it in every run, plus one NAT'd office. Those are the false alerts. It also catches the password sprayer, which is the bonus column.
- **At an attacker's own rate (3):** the low-and-slow attacker hovers around three failures per five minutes, so the condition keeps lapsing and re-firing: one attack becomes about 18 alerts per run. Each stuffing address that tried three passwords also raises its own alert, about 8 per run. Both land in the duplicate column. A threshold sitting on top of an attacker's rate produces alert flapping, not detection.
- **Too high (26):** recall halves. The brute force that *succeeded* took 25 attempts, so it is the one that gets missed, while the noisier 40-attempt failure is still caught. A threshold tuned to the loud attack misses the one that mattered.
- **Higher still (45):** nothing is detected.

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
| 3 | 50 / 50 | 58 | 4 | 0 | 4 | 93.1% | 100.0% |
| 7 | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 15 (shipped) | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 25 | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 28 | 0 / 50 | 0 | 0 | 0 | 0 | n/a | 0.0% |

- The simulated attack uses 25 addresses. Above that the rule can only fire when unrelated failures happen to overlap it, and at 28 that never happens in these runs.

### Success after failures: failed logins required before the successful one

| `ssh-success-after-failures` first-step threshold | Detected | Alerts | False | Duplicate | Bonus | Precision | Recall |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 50 / 50 | 400 | 350 | 0 | 0 | 12.5% | 100.0% |
| 3 | 50 / 50 | 65 | 15 | 0 | 0 | 76.9% | 100.0% |
| 5 (shipped) | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 25 | 50 / 50 | 50 | 0 | 0 | 0 | 100.0% | 100.0% |
| 26 | 0 / 50 | 0 | 0 | 0 | 0 | n/a | 0.0% |

- **At 1**, anyone who ever mistyped a password and then logged in is an alert: seven false alerts per run.
- **At 3**, the user who mistypes three times is flagged, in the runs where that happens.
- **At 26**, the attack is missed, because it succeeded on the 26th attempt after 25 failures.

Grouping matters as much as the threshold. Grouped by address and username (shipped), `ssh-success-after-failures` raises 0 false alerts across these runs. Grouped by address alone it raises 4. All of those are the NAT'd office: several people mistype, then somebody else logs in, and by address alone that looks like a guess that worked.

### Impossible travel: the fastest plausible speed, in km/h

| `ssh-impossible-travel` max_speed_kmh | Detected | Alerts | False | Duplicate | Bonus | Precision | Recall |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 300 | 50 / 50 | 150 | 100 | 0 | 0 | 33.3% | 100.0% |
| 900 (shipped) | 50 / 50 | 100 | 50 | 0 | 0 | 50.0% | 100.0% |
| 5000 | 50 / 50 | 100 | 50 | 0 | 0 | 50.0% | 100.0% |
| 50000 | 0 / 50 | 0 | 0 | 0 | 0 | n/a | 0.0% |

- **At 300**, the legitimate traveller (London to New York in 14 hours, about 400 km/h) is flagged as well.
- **At 900 and at 5,000**, the VPN user is still flagged: their apparent speed is about 33,000 km/h.
- **At 50,000**, the VPN user is finally ignored, and so is the thief, at about 41,000 km/h.

No speed separates the VPN user from the thief, because both are teleporting. Fixing this false positive needs different information (known VPN and hosting networks, device or key fingerprints, a per-user allow list), not a different number.

## Known gaps

- **VPN users** trip the impossible-travel rule. Documented false positive, measured above.
- **Low-and-slow** attacks are missed at these thresholds. Catching them needs a longer window or a different signal, not a lower threshold: the brute-force sweep shows what lowering it does.
- **Address rotation.** An attacker spreading a brute force across many addresses stays under the per-address rule. The stuffing rule covers the many-addresses-one-host shape, but only above 15 sources in ten minutes.
- **Locations are only as good as GeoIP**, and events with no location are invisible to the travel rule.
- **Simulated data only.** The simulator's traffic is cleaner and more regular than real logs. Expect these numbers to drop on a real server's logs. The honeypot cannot stand in for one: it accepts nearly every login, so its data has almost no failures for these rules to count.

## Reproduce

```bash
python -m siftlog.evaluate --published
```

A test (`tests/test_results_doc.py`) regenerates every table on this page, and the grouping comparison, and fails if the page is out of date.
