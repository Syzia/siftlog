# Honeypot runbook (stage 0)

Goal: a [Cowrie](https://docs.cowrie.org) SSH honeypot on an isolated VPS, collecting real attack data for Siftlog to detect on later (stage 8).

Cowrie steps were checked against docs.cowrie.org on 2026-10-13. Steps marked **(not from Cowrie docs)** are standard Ubuntu/systemd practice that I could not confirm from Cowrie's own pages, so verify them on the box.

Written for **Debian 12 (bookworm)** or **Ubuntu 24.04 LTS**. Cowrie's docs say their package list was last verified on Debian Bookworm, so prefer it when the plan offers it. The smallest plans (0.5 GB RAM) work with the swap file in step 2; the plan must include a public **IPv4** address, because internet-wide SSH scanning does not happen over IPv6.

**Verified on a real deployment (2026-10-13):** Vultr `vc2-1c-1gb`, Ubuntu 24.04.5, Cowrie 3.1.2. On that image `ufw` is active and allows only 22/tcp, and `ssh.socket` is inactive, so the drop-in port change in step 4 is the one that applies.

Placeholders: `<IP>` is the server's public address, `<MY_IP>` is your current public address, and `22222` is the admin SSH port (any high port works).

## Ground rules

- **Throwaway box.** Nothing personal on it, no reused keys or passwords, nothing that can reach your other systems. Use the dedicated `~/.ssh/honeypot_ed25519` key and never enable SSH agent forwarding to it.
- **The box will download attackers' payloads.** Cowrie records `cowrie.session.file_download` events with a `url`, `outfile` and `shasum`, which means it fetches and stores the files attackers ask for. Treat everything it stores as live malware: never open, run or `chmod +x` it, and keep it off your Mac. Watch disk usage.
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

Pull logs to a folder outside the repo:

```bash
rsync -av -e "ssh -i ~/.ssh/honeypot_ed25519 -p 22222" root@<IP>:/home/cowrie/my-honeypot/var/log/cowrie/ ~/honeypot-logs/
```

Per the Cowrie docs, every JSON event carries `eventid`, `message`, `sensor`, `timestamp` (ISO 8601, UTC), `session` and `src_ip`. The ones Siftlog cares about:

| `eventid` | Extra fields |
|-----------|--------------|
| `cowrie.session.connect` | `src_port`, `dst_ip`, `dst_port` |
| `cowrie.login.failed` / `cowrie.login.success` | `username`, `password` (or `fingerprint`, `key`, `type` for public-key attempts) |
| `cowrie.command.input` | `input` |
| `cowrie.session.file_download` | `url`, `outfile`, `shasum` |

These map onto `auth_failure` and `auth_success` events. There is no Cowrie parser yet; that is the first task of stage 8.

## 12. Teardown

Destroy the instance in the Vultr console (this is the only thing that stops billing), delete the firewall group, and remove the stale host key:

```bash
ssh-keygen -R <IP>
```
