# Commands

Every command used to run Siftlog and its honeypot, in one place.

This page is generated from `siftlog/api/static/commands.json`. The dashboard shows the same list with this machine's own values filled in, ready to paste. Here, `<path to the siftlog folder>` and `<HONEYPOT_IP>` stand in for them.

## Start here

The two you will use most.

### Open this dashboard

*On your Mac.*

Starts the API and opens the dashboard in your browser, already signed in. Stop it with Ctrl+C.

```bash
cd "<path to the siftlog folder>" && .venv/bin/python -m siftlog.api --db siftlog.db --rules rules --open
```

### Run the tests

*On your Mac.*

Should end with a line like "284 passed".

```bash
cd "<path to the siftlog folder>" && .venv/bin/python -m pytest -q
```

## Simulated data, step by step

Generate a labelled practice log and run it through the whole pipeline. Each step is safe to repeat.

### 1. Generate a practice log

*On your Mac.*

Writes data/demo.log and a label file saying which lines belong to which attack.

```bash
cd "<path to the siftlog folder>" && .venv/bin/python -m siftlog.simulator --seed 1234 --out data/demo.log
```

### 2. Parse it into the database

*On your Mac.*

```bash
cd "<path to the siftlog folder>" && .venv/bin/python -m siftlog.ingest data/demo.log --db siftlog.db --year 2026
```

### 3. Add locations

*On your Mac.*

The impossible-travel rule needs these.

```bash
cd "<path to the siftlog folder>" && .venv/bin/python -m siftlog.enrich --db siftlog.db --simulated
```

### 4. Run the rules and save the alerts

*On your Mac.*

Never erases a decision you recorded on an alert.

```bash
cd "<path to the siftlog folder>" && .venv/bin/python -m siftlog.engine --db siftlog.db --rules rules --save
```

### Measure the rules across 50 simulations

*On your Mac.*

Prints the tables in docs/results.md. Takes about ten seconds.

```bash
cd "<path to the siftlog folder>" && .venv/bin/python -m siftlog.evaluate --published
```

## Live detection

Follow a log as it grows. Alerts appear here within a couple of seconds.

### Follow a log file

*On your Mac.*

Prints ALERT and update lines as they happen. Run it in its own Terminal window; stop it with Ctrl+C.

```bash
cd "<path to the siftlog folder>" && .venv/bin/python -m siftlog.watch data/demo.log --db siftlog.db --rules rules --year 2026 --simulated-geo
```

### Send a fake attack to the followed log

*On your Mac.*

Twelve failed logins stamped with the current time, so each run counts as newer than the last. Run it in a second window while the follower is running.

```bash
cd "<path to the siftlog folder>" && NOW=$(date -u +%Y-%m-%dT%H:%M:%S) && for i in $(seq 0 11); do printf '%s.%06d+00:00 web01 sshd[1]: Failed password for root from 203.0.113.77 port 22 ssh2\n' "$NOW" "$i" >> data/demo.log; done
```

## Honeypot: from your Mac

The honeypot keeps running whether or not you are connected.

### Log in to the honeypot server

*On your Mac.*

Asks for your key passphrase. The prompt changes to root@HoneyPot. Type exit to leave.

```bash
ssh -i ~/.ssh/honeypot_ed25519 -p 22222 root@<HONEYPOT_IP>
```

### Watch attacks arrive, in one step

*On your Mac.*

Any address that is not yours is a real visitor. Ctrl+C stops watching and disconnects.

```bash
ssh -i ~/.ssh/honeypot_ed25519 -p 22222 -t root@<HONEYPOT_IP> 'tail -f /home/cowrie/my-honeypot/var/log/cowrie/cowrie.log'
```

### Copy the honeypot's logs to this Mac

*On your Mac.*

Copies into a folder outside the repo. Never copy anything from the downloads folder: that is live malware.

```bash
mkdir -p ~/honeypot-logs && rsync -av -e "ssh -i ~/.ssh/honeypot_ed25519 -p 22222" root@<HONEYPOT_IP>:/home/cowrie/my-honeypot/var/log/cowrie/ ~/honeypot-logs/
```

## Honeypot: after logging in

Run these at the root@HoneyPot prompt.

### Is it running?

*On the honeypot (after logging in).*

You want active, active, and a LISTEN line.

```bash
systemctl is-active cowrie cowrie-redirect; ss -tln | grep ':2222 '
```

### Who has visited

*On the honeypot (after logging in).*

Log entries per address, busiest first.

```bash
grep -o '"src_ip":"[^"]*"' /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json | sort | uniq -c | sort -rn | head -20
```

### Usernames and passwords tried

*On the honeypot (after logging in).*

```bash
grep -o '"message":"login attempt[^"]*"' /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json | sort | uniq -c | sort -rn | head -20
```

### Files uploaded or downloaded

*On the honeypot (after logging in).*

Each record has a shasum you can search for on VirusTotal. Search by hash only; never upload or open the file.

```bash
grep -E 'file_upload|file_download' /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json | tail -5
```

### Disk space and stored payloads

*On the honeypot (after logging in).*

Worth a look about once a week.

```bash
df -h / && ls -la /home/cowrie/my-honeypot/var/lib/cowrie/downloads/
```

### Restart Cowrie

*On the honeypot (after logging in).*

Needed after changing its config. Down for a couple of seconds.

```bash
systemctl restart cowrie && systemctl is-active cowrie
```

### Leave the server

*On the honeypot (after logging in).*

Only hangs up your connection. The honeypot keeps recording.

```bash
exit
```

## Project housekeeping

### What has changed

*On your Mac.*

```bash
cd "<path to the siftlog folder>" && git status -sb && git log --oneline -8
```

### Open pull requests

*On your Mac.*

```bash
cd "<path to the siftlog folder>" && gh pr list
```
