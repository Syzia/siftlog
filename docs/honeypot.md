# Honeypot runbook (stage 0)

Goal: a [Cowrie](https://docs.cowrie.org) SSH honeypot on an isolated VPS, collecting real attack data for Siftlog to detect on later (stage 8).

Cowrie steps were checked against docs.cowrie.org on 2026-10-13. Steps marked **(not from Cowrie docs)** are standard Ubuntu/systemd practice that I could not confirm from Cowrie's own pages, so verify them on the box.

Written for **Debian 12 (bookworm)** or **Ubuntu 24.04 LTS**. Cowrie's docs say their package list was last verified on Debian Bookworm, so prefer it when the plan offers it. The smallest plans (0.5 GB RAM) work with the swap file in step 2; the plan must include a public **IPv4** address, because internet-wide SSH scanning does not happen over IPv6.

**Verified on a real deployment (2026-10-13):** Vultr `vc2-1c-1gb`, Ubuntu 24.04.5, Cowrie 3.1.2. On that image `ufw` is active and allows only 22/tcp, and `ssh.socket` is inactive, so the drop-in port change in step 4 is the one that applies.

Placeholders: `<IP>` is the server's public address, `<MY_IP>` is your current public address, and `22222` is the admin SSH port (any high port works).

## Ground rules

- **Throwaway box.** Nothing personal on it, no reused keys or passwords, nothing that can reach your other systems. Use the dedicated `~/.ssh/honeypot_ed25519` key and never enable SSH agent forwarding to it.
- **The box will store attackers' payloads.** Cowrie fetches the files attackers ask it to download and keeps the files they upload, recording each with a `shasum`. Treat everything in `var/lib/cowrie/downloads` as live malware: never open, run or `chmod +x` it, and keep it off your Mac. There is no size limit until you set one (step 5).
- **Raw logs never go in the repo.** Keep them outside it (for example `~/honeypot-logs`). Fixtures are sanitized by hand.
- **Billing is hourly and continues while stopped.** Only destroying the instance stops it.

## 1. Vultr firewall group (before opening anything)

Under Network, then Firewall, create a group and attach it to the instance. Start with **one rule per port, source limited to `<MY_IP>/32`**:

| Protocol | Port | Source |
|----------|------|--------|
| TCP | 22 | `<MY_IP>/32` (temporary, for first login) |
| TCP | 22222 | `<MY_IP>/32` (permanent admin port) |

Port 22 is opened to the world only in step 8, once Cowrie is listening. If your home IP changes you can lock yourself out; Vultr's web console (View Console) always works as a fallback.

## 2. First login and updates

```bash
ssh -i ~/.ssh/honeypot_ed25519 root@<IP>
```

```bash
apt-get update && apt-get -y upgrade
```

On a plan with less than 1 GB of RAM, add swap first so installs and traffic bursts cannot run the box out of memory **(not from Cowrie docs)**. Check whether swap already exists:

```bash
swapon --show
```

If that prints nothing, create a 1 GB swap file and make it permanent:

```bash
fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
```

```bash
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

## 3. Check the host firewall (not from Cowrie docs)

Vultr's Ubuntu images may ship with `ufw` enabled. A redirect to 2222 (step 7) is filtered *after* it happens, so the host firewall must allow the admin port and 2222.

```bash
ufw status
```

If it says `active`:

```bash
ufw allow 22222/tcp && ufw allow 2222/tcp && ufw allow 22/tcp
```

If it says `inactive` or `command not found`, there is no host firewall and you can skip this step.

## 4. Move the real SSH server off port 22 (not from Cowrie docs)

Cowrie's docs say to relocate the existing SSH server but give no commands. Do this carefully, and **keep your first session open until the new port is proven**.

Ubuntu may run sshd under systemd socket activation, in which case `Port` in `sshd_config` is ignored. Check:

```bash
systemctl is-active ssh.socket
```

If it prints `active`, change the socket instead:

```bash
systemctl edit ssh.socket
```

Put this in the override, which clears the old listener and sets the new one:

```
[Socket]
ListenStream=
ListenStream=22222
```

```bash
systemctl daemon-reload && systemctl restart ssh.socket
```

If it prints `inactive` (the normal case on Debian 12), set the port with a drop-in file instead. The main config includes this directory first, so no editor is needed:

```bash
echo 'Port 22222' > /etc/ssh/sshd_config.d/00-port.conf && sshd -t && systemctl restart ssh
```

Confirm it is listening:

```bash
ss -tlnp | grep 22222
```

**In a second terminal on your Mac**, prove the new port works before touching anything else:

```bash
ssh -i ~/.ssh/honeypot_ed25519 -p 22222 root@<IP>
```

Then turn off password logins. A file named `00-` is read first, and sshd uses the first value it finds, so this wins over cloud-init's drop-ins:

```bash
printf 'PasswordAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/00-hardening.conf && sshd -t && systemctl reload ssh
```

## 5. Install Cowrie (from the Cowrie docs)

System packages:

```bash
apt-get install python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind
```

Cowrie refuses to run as root, so create an unprivileged user and switch to it:

```bash
adduser --disabled-password --gecos "" cowrie
```

```bash
su - cowrie
```

As the `cowrie` user:

```bash
mkdir ~/my-honeypot && cd ~/my-honeypot
python3 -m venv cowrie-env
source cowrie-env/bin/activate
python -m pip install --upgrade pip
python -m pip install cowrie
cowrie init
```

`cowrie init` writes `etc/cowrie.cfg` and the `var/` skeleton. Settings are layered, and your `etc/cowrie.cfg` only needs the keys you change. For example, telnet is off by default and is enabled with `[telnet] enabled = true`. Leave it off for the first deployment.

**Cap transfer sizes before starting it.** Out of the box Cowrie puts no limit on what an attacker can upload, or make the honeypot download: the setting ships commented out. On the live box the first visitor logged in and uploaded a 30 MB file within the hour. Turn the limit on (10 MB is Cowrie's own suggested value):

```bash
sed -i 's/^#download_limit_size = 10485760/download_limit_size = 10485760/' etc/cowrie.cfg && grep -n '^download_limit_size' etc/cowrie.cfg
```

It should print the now-active line (line 87 in Cowrie 3.1.2, under `[honeypot]`). The one setting covers SFTP uploads as well as `wget`, `curl`, `tftp`, `ftpget` and `nc`. It is a per-file limit, so different payloads still add up: check `df -h /` now and then. If Cowrie is already running, apply the change with `systemctl restart cowrie` as root. **(Verified on the live box.)**

Start it (from the same directory, venv active):

```bash
cowrie start
```

It listens on **2222** by default and writes logs to `./var/log/cowrie/`. `cowrie stop` stops it.

## 6. Test it locally

Exit back to root (`exit`), then:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@127.0.0.1
```

Whether or not the login succeeds, it should be logged:

```bash
ls -la /home/cowrie/my-honeypot/var/log/cowrie/
```

Confirmed on the live box: the directory holds `cowrie.json` (one JSON event per line, what Siftlog will parse) and `cowrie.log` (human-readable text). Downloaded payloads go to `var/lib/cowrie/downloads`.

## 7. Redirect port 22 to Cowrie (from the Cowrie docs)

```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

The docs note this does not apply to loopback, so test from another machine (step 9), not from the server.

This rule lasts until the next reboot. **Do not install `iptables-persistent` to keep it**: on Ubuntu 24.04 that package is marked as conflicting with `ufw`, and apt may remove the host firewall to install it. Persistence is handled in step 10 instead.

## 8. Test from your Mac while port 22 is still restricted to you

The Vultr firewall still only lets `<MY_IP>` reach port 22, so you can be the first "attacker". Run this on your Mac, not the server:

```bash
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PubkeyAuthentication=no root@<IP>
```

The options keep Cowrie's host key out of your Mac's `known_hosts` (so the admin port keeps working without warnings) and stop your real keys being offered to the honeypot. Type any password. Cowrie's default accounts accept most passwords for `root`; whether or not you get its fake shell, the attempt is recorded. Type `exit` to leave.

Then, on the server as root, confirm it was captured:

```bash
tail -n 5 /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
```

You should see `cowrie.session.connect` and `cowrie.login.success` or `cowrie.login.failed` events carrying your IP.

## 9. Open port 22 to the world

Only after step 8 works: in the Vultr firewall group, change the port 22 rule's source to anywhere (`0.0.0.0/0`). Leave the 22222 rule restricted to `<MY_IP>/32`. Port 2222 never needs to be opened externally.

Scanners find a new address within hours, and real events start arriving.

## 10. Keeping it alive

`cowrie start` survives logging out but **not a reboot**, and neither does the iptables rule from step 7. Two systemd units fix both **(not from Cowrie docs; verified on the live box, including a reboot)**.

Paste each block whole, as root, one at a time. If a log viewer such as `tail -f` is running, press Ctrl+C first, or the paste is typed into it instead of being run.

```bash
cat > /etc/systemd/system/cowrie.service <<'EOF'
[Unit]
Description=Cowrie SSH honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/my-honeypot
Environment=PATH=/home/cowrie/my-honeypot/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin
Environment=VIRTUAL_ENV=/home/cowrie/my-honeypot/cowrie-env
ExecStartPre=/bin/rm -f /home/cowrie/my-honeypot/var/run/cowrie.pid
ExecStart=/home/cowrie/my-honeypot/cowrie-env/bin/cowrie start
ExecStop=/home/cowrie/my-honeypot/cowrie-env/bin/cowrie stop
PIDFile=/home/cowrie/my-honeypot/var/run/cowrie.pid
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

The two `Environment` lines stand in for activating the virtualenv, which `cowrie start` needs in order to find `twistd`. The `rm -f` clears a stale PID file left by an unclean shutdown.

```bash
cat > /etc/systemd/system/cowrie-redirect.service <<'EOF'
[Unit]
Description=Redirect port 22 to Cowrie on port 2222
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 2>/dev/null || iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222'

[Install]
WantedBy=multi-user.target
EOF
```

The `-C` check means the rule is only added when it is missing, so it is never duplicated.

Stop the hand-started copy, then start and enable both units:

```bash
su - cowrie -c 'cd ~/my-honeypot && . cowrie-env/bin/activate && cowrie stop'
```

```bash
systemctl daemon-reload && systemctl enable --now cowrie-redirect cowrie
```

Check, then `reboot` and check again after reconnecting on the admin port:

```bash
systemctl is-active cowrie cowrie-redirect; ss -tln | grep ':2222 '; iptables -t nat -S PREROUTING
```

You want `active` twice, a `LISTEN` line for 2222, and exactly one `--dport 22 -j REDIRECT --to-ports 2222` rule.

You can also verify from outside without logging in, by reading the SSH banners. The admin port shows the real server (`OpenSSH_9.6p1 Ubuntu`), and port 22 shows Cowrie's fake one (`OpenSSH_9.2p1 Debian`):

```bash
(sleep 4 | nc -w 8 <IP> 22 | head -c 100)
```

Cowrie's docs also have an "Updating Cowrie" section. Read it before leaving the box for weeks.

## 11. Getting logs to Siftlog (stage 8)

Three steps, all on your Mac. The dashboard's Commands tab has them with your own values filled in.

**1. Copy the logs** to a folder outside the repo. It only fetches what is new, so repeat it whenever you want fresh data:

```bash
mkdir -p ~/honeypot-logs && rsync -av -e "ssh -i ~/.ssh/honeypot_ed25519 -p 22222" root@<IP>:/home/cowrie/my-honeypot/var/log/cowrie/ ~/honeypot-logs/
```

The folder ends up with `cowrie.json` (today) and the matching `cowrie.log` text file. Cowrie starts a new pair each night and renames the old ones with their date. Siftlog reads the JSON ones.

**2. Parse them** into a database of their own, in the git-ignored `data/` folder:

```bash
cd <path to the siftlog folder> && .venv/bin/python -m siftlog.ingest ~/honeypot-logs/cowrie.json* --source cowrie --db data/honeypot.db --show-ignored --ignore-ip <YOUR_OWN_IP>
```

Safe to repeat: lines already stored are skipped, including after Cowrie's nightly rename of `cowrie.json`. `--ignore-ip` leaves out your own test logins. Without it, expect an alert about yourself.

**3. Run the rules and look:**

```bash
cd <path to the siftlog folder> && .venv/bin/python -m siftlog.engine --db data/honeypot.db --rules rules --save
cd <path to the siftlog folder> && .venv/bin/python -m siftlog.api --db data/honeypot.db --rules rules --port 8010 --open
```

### What becomes an event

Every Cowrie record carries `eventid`, `timestamp` (ISO 8601, UTC), `session`, `src_ip` and `sensor`.

| Cowrie `eventid` | Siftlog event | Kept from the record |
|------------------|---------------|----------------------|
| `cowrie.session.connect` | `connection` | |
| `cowrie.login.failed` / `cowrie.login.success` | `auth_failure` / `auth_success` | `username`, `password` (or key `fingerprint`) |
| `cowrie.command.input` | `command` | `input` |
| `cowrie.session.file_upload` | `file_transfer` | `filename`, `shasum` |
| `cowrie.session.file_download` (and `.failed`) | `file_transfer` | `url`, `destfile`, `shasum` |

A `file_download` is not always a download. Cowrie writes the same record, with no `url`, when a shell command creates a file, as in `echo key >> .ssh/authorized_keys`. Siftlog marks those `written` and keeps `destfile`, the path that was written. In the first three hours of real data, 16 of the 17 file events were this kind.

Everything else is ignored and counted: `--show-ignored` prints how many of each. If one of those counts turns out to be interesting, that is the cue to map it.

### What the rules look for

A honeypot is not a server with users, and two things about its data shape the rules:

- **Almost every login succeeds.** Cowrie lets most guesses in, so there are very few failures. The `ssh-*` rules, which count failures, do not read this data at all.
- **Every visitor is hostile.** An alert per login would be noise. The rules pick out the visitors who did something after getting in.

| Rule | Fires when one address | Severity |
|------|------------------------|----------|
| `honeypot-file-transfer` | uploads a file, makes the honeypot download one (failed downloads included), or writes one with a shell command | high |
| `honeypot-shell-commands` | runs any command after logging in | medium |
| `honeypot-credential-sweep` | tries five or more usernames within ten minutes | low |

One visit is one alert. The same address coming back hours later is a new one.

`honeypot-shell-commands` is the noisy one. It cannot tell a lone `uname` from a malware install, because rules cannot yet match on the text of a command. Read the high-severity alerts first.

**After changing the parser, rebuild the database.** Ingest skips lines it has already stored, so events parsed by an older version keep their old fields. Delete `data/honeypot.db` and run step 2 again. Decisions recorded on its alerts are lost with it.

The first upload captured was a 30 MB file named `sshd`: malware masquerading as the SSH daemon (MITRE ATT&CK T1036.005). `dst_port` in every record is 2222, not 22, because of the redirect in step 7.

**Passwords are in this data on purpose.** They are attackers' guesses, and the list of what gets tried is one of the points of running a honeypot. It is also why the copied logs and `data/honeypot.db` must stay out of git.

## 12. Teardown

Destroy the instance in the Vultr console (this is the only thing that stops billing), delete the firewall group, and remove the stale host key:

```bash
ssh-keygen -R <IP>
```
