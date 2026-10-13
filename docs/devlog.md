# Dev log

Important findings, mistakes and decisions, newest first. This is the "what actually happened" record: the things that were not in the plan, and the things the plan got wrong.

Attacker addresses and file hashes are deliberately not recorded here, in line with the rule that no live attack data goes in the repo. They are in the honeypot's own `cowrie.json`, and each entry below names the session id to search for.

---

## 2026-10-13: Honeypot data through the pipeline (stage 8)

**Summary.** Siftlog can now read the honeypot's own log format. A Cowrie parser, three honeypot rules, and a way to leave your own visits out. Built from the layout of real records and Cowrie's documentation, and tested against an invented log in that layout.

- **The existing rules were the wrong rules.** All five count failed logins or compare logins by one user. A honeypot lets nearly everyone in, so the four that count failures would mostly sit silent. The travel rule, once events had locations, would flag `root` again and again, because everyone logs in as root from everywhere. So each rule now names the source it reads, and the honeypot has its own three.
- **What is interesting on a honeypot is what happens after the login.** An alert for every login would fire on every visitor. The rules fire on the visitors who ran a command or brought a file.
- **Adding rules nearly spoiled the results table.** The three new rules cannot fire on simulated sshd data, and the first run of the published table showed them as three rows of zeros that read like a result. Rules that cannot read the data being scored are now left out and named underneath.
- **`ip_address(5)` is a valid address.** Python's address check accepts integers, so a record with a number where the source address belongs passed validation and produced an event whose address was not a string. Noticed while writing the tests for wrong types, before it reached any data.
- **A `$` in a pattern allows a trailing newline.** `"cowrie.login.failed\n"` matched the event-id pattern. Harmless here, since JSON decoding has already split lines, but both patterns now match the whole string.
- **One deliberate bug went unnoticed.** Of 30 planted in a scratch copy, the tests caught 29. Shortening the file-transfer rule's window from an hour to five seconds changed nothing, because the test data's transfers were three seconds apart. There is now a test with transfers 50 minutes apart, and one with a return visit six hours later.
- **Cowrie writes compact JSON.** No spaces after colons or commas. The first draft of the test log had them. It parsed either way, but the `grep` commands in the runbook only match the compact form, so the test log now matches what Cowrie really writes.

**Not done, and worth knowing.** The rule thresholds are first guesses from one day of traffic. Tunnelling requests (`cowrie.direct-tcpip.request`), where a visitor uses the honeypot as a relay, are counted but not yet turned into events. Locations are not added to honeypot events, since that needs a GeoIP database. A record longer than 64 KiB is cut short and lands in the dead-letter table.

---

## 2026-10-13: Local dashboard (stage 7)

**Summary.** The API now serves a dashboard: overview, alerts with their evidence and a decision workflow, event search, and a copyable command list. It was checked in a real browser against live data, including the real honeypot.

- **Not React, on purpose.** One HTML file, one stylesheet and one script. There is nothing to install or build, and nothing is fetched from the internet.
- **`append(null)` prints the word "null".** The first render showed it in the middle of the honeypot panel. Building everything through one helper that skips missing pieces fixed it; the browser check is what caught it, since no Python test looks at rendered output.
- **Pasting a token was the hardest part of the API for a newcomer.** An abbreviated token shown in a chat message got pasted as if it were the real one, and every request came back 401. The server now prints a link that signs the dashboard in by itself.
- **A demo command taught the wrong lesson.** It stamped its lines with fixed times, so running it twice looked like old data and was skipped by live detection. The version in the command list stamps lines with the current time.
- **Checking the honeypot is itself a visit.** A check on a timer would have filled the honeypot's data with this machine's address, so it runs only on a click and the answer is kept for a minute.

---

## 2026-10-13: Live detection (stage 6)

**Summary.** One process now follows a log file and raises alerts within about two seconds. Three problems surfaced while building it, none of which the first round of tests caught.

- **The log follower returned garbage after an in-place rewrite.** When a file was overwritten with longer content, it read from its old position in the *new* content, producing half a line, and only then noticed the change. It now checks for an in-place rewrite before reading. A rename is the opposite case: there the old file is still intact, and must be read to its end first.
- **It could not be stopped cleanly by anything but Ctrl+C.** `kill` and systemd send a different signal, which ended the process without evaluating the events it was still holding. Found because a test script hung: a process started in the background ignores Ctrl+C-style interrupts. There is now a test that runs the real command and stops it with that signal.
- **Two checks looked redundant and were not.** The truncation check never mattered in the first truncation test, because the first line also changed. It matters when a file is cut shorter but keeps its first line. Likewise nothing tested that a file rotated in on 1 January continues the year the old file had reached.

Design points worth remembering: the watcher rebuilds everything from the store when it starts, which is what makes a restart mid-attack safe; and its two-second wait is how slightly out-of-order events get put right.

---

## 2026-10-13: First real attacker, and an unlimited upload

**Summary.** Within about an hour of opening the honeypot to the internet, a bot guessed a password, logged in, and uploaded a 30 MB file named `sshd`. The upload exposed a gap in our setup: Cowrie had no limit on transfer size. The limit is now on, and the runbook requires it.

### What happened (times in UTC)

| Time | Event |
|------|-------|
| 02:06 | Honeypot rebooted as a test. Cowrie and the port 22 redirect came back on their own. |
| later | Port 22 opened to the world in the Vultr firewall. The exact time was not noted. |
| 03:31:04 | One address logged in as `root` with the password `ubuntu`. Cowrie accepted it, as designed. |
| 03:31 to 03:35 | That session uploaded a file over SFTP, about four chunks a second. |
| 03:35:33 | Upload completed: **30,304,472 bytes, filename `sshd`**. Cowrie stored it under its SHA-256 in `var/lib/cowrie/downloads/`. |

By then eight different outside addresses had connected. Four had attempted a login and all four succeeded: `root/ubuntu`, `root/son`, `root/123@123`, `jenkins/jenkins`. Three more connected and left without trying, which is what a port scanner looks like.

To see everything from the uploading session on the honeypot:

```bash
grep b7f4e33dcbed /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
```

### What it means

- **The filename is the interesting part.** `sshd` is the name of the real SSH server program. A 30 MB file with that name is malware dressed as a system process, so it does not stand out in a process list. The technique is called masquerading (MITRE ATT&CK T1036.005).
- **Nothing was compromised.** Cowrie only pretends to be a server. The file was saved, never run, and the attacker was typing into a fake shell. The real SSH service is on a different port and only accepts one key from one address.

### The gap it exposed

Cowrie's transfer size limit, `download_limit_size`, **ships commented out**, which means no limit. One setting covers SFTP uploads as well as `wget`, `curl`, `tftp`, `ftpget` and `nc` (confirmed by reading `shell/filetransfer.py` in the installed package, where the fallback is 0).

At roughly 100 KB a second with 16 GB free, one upload would take over a day to fill the disk, so this was a slow leak and not an emergency. But a full disk stops the honeypot logging, and it was meant to run unattended for weeks.

### The fix

On the honeypot, as root:

```bash
sed -i '87s/^#download_limit_size = 10485760/download_limit_size = 10485760/' /home/cowrie/my-honeypot/etc/cowrie.cfg
systemctl restart cowrie
```

Verified afterwards: the line is active under `[honeypot]`, the service is `active`, and it is listening on 2222. The limit is 10 MB per file, Cowrie's own suggested value. [The runbook](honeypot.md) now has this as a required step before Cowrie is first started.

### What was assumed wrong

The working assumption was that Cowrie capped uploads at about 10 MB by default. It came from memory and it was wrong: that number is the *suggested* value in a commented-out line. A directory listing showing a 26 MB file still growing is what corrected it. Lesson: for anything about a tool's defaults, read the installed config instead of recalling it.

### Lessons for the project

- **A honeypot lets almost every guess in**, so this data has very few failed logins. The rules that count failures (brute force, spraying, stuffing) will be quiet on it. The signals in honeypot data are successful logins from many addresses, the commands typed, and uploads.
- **Uploads are their own event**, `cowrie.session.file_upload`, with `filename`, `outfile` and `shasum`. The Cowrie parser needs to keep them, and a rule on uploads, or on filenames that imitate system programs, would have flagged this.
- **A per-file limit is not a total limit.** Different payloads still add up.

### Still to do

- Look the file's hash up on VirusTotal (search by hash only; never upload or open the file).
- Check `df -h /` on the honeypot about once a week.
- Build the Cowrie parser against this data (stage 8), after a day or two more has accumulated.

---

## 2026-10-13: Lessons from building stages 0 to 5

Shorter notes on things that were not in the plan. Each one changed the design or the docs.

### Design mistakes found while building

- **Alerts must follow the rule's condition, not the event stream.** The plan said an alert stays open "while matching events keep arriving". For a rule grouped by host those never stop on an internet-facing server, so the first alert would stay open forever and swallow every later attack. An alert now stays open only while its condition holds. Regression test: `test_host_level_alert_closes_even_though_failures_never_stop`.
- **A scorer that punishes catching an attack is wrong.** The first scorer called an alert false if it did not match an *expected* scenario, so a rule that caught the low-and-slow attacker was penalised. Alerts are now judged on their own evidence: false means mostly benign evidence, and duplicates and unexpected catches are counted separately.
- **Perfect scores were a warning sign, twice.** The travel rule scored zero false alerts only because nothing in the simulation could fool it. A VPN user was added as a documented false positive, the mirror of the low-and-slow documented miss. No speed threshold separates the two: the VPN user "moves" at 33,000 km/h and a thief at 41,000.
- **Group the "guess that worked" rule by address and username.** By address alone it fires on a NAT'd office where several people mistype and someone else logs in.

### Things deliberate breakage found

Breaking the code on purpose and checking that a test fails found gaps that passing tests hid.

- A test of "hostile username cannot spoof the source address" passed even with the bug it was meant to catch. The real risk is a username containing a complete fake `from <ip> port <n> ssh2` tail, and that case was missing.
- "Only check a sequence when its final step arrives" looked like a pure speed-up. Removing it changed behaviour: a stray failure after the successful login became evidence. It is a definition, and it now has a test.

### Honeypot setup traps

- **Do not install `iptables-persistent` on Ubuntu 24.04 with `ufw` active.** The packages conflict and apt may remove the firewall. Two small systemd units restore the port 22 redirect and start Cowrie at boot instead.
- **Cowrie's install procedure changed.** It is now `pip install cowrie` and `cowrie init`, not a git clone. Checking the current docs caught this before it cost anything.
- **Moving the real SSH port is the lockout risk.** Keep the first session open, and prove the new port from a second terminal before changing anything else.
- **`ufw` filters after the redirect**, so port 2222 must be allowed on the host as well as 22.
- **Pasting commands while `tail -f` is running does nothing.** They are typed into the viewer. Press Ctrl+C first.
- **A cheap IPv6-only plan is useless for a honeypot.** Internet-wide SSH scanning happens over IPv4.

### Smaller ones worth remembering

- **Syslog timestamps have no year.** Ingest requires `--year` instead of guessing, because a wrong guess silently corrupts every timestamp.
- **Identify a log by its first line, not its path.** Otherwise a rotated, renamed or gzipped copy is counted twice.
- **Skip a final line with no newline.** Event ids are offset-based, so storing a half-written line would be permanent.
- **SQLite's WAL sidecar files** (`-wal`, `-shm`) are not covered by ignoring `*.db`.
- **An API's bare address should lead somewhere.** A 404 at `/` reads as "the server is broken". It now redirects to `/docs`.
- **Use `.venv/bin/python`.** The Mac's system Python is 3.9 and has none of the dependencies.
- **`/stats` surfaces what the rules miss.** The busiest failing source in the simulation is the low-and-slow attacker that no rule fires on.
