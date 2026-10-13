# Honeypot runbook (stage 0)

Goal: a [Cowrie](https://docs.cowrie.org) SSH honeypot on an isolated VPS, collecting real attack data for Siftlog to detect on later (stage 8).

Cowrie steps were checked against docs.cowrie.org on 2026-10-13. Steps marked **(not from Cowrie docs)** are standard Ubuntu/systemd practice that I could not confirm from Cowrie's own pages, so verify them on the box.

Written for **Debian 12 (bookworm)** or **Ubuntu 24.04 LTS**. Cowrie's docs say their package list was last verified on Debian Bookworm, so prefer it when the plan offers it. The smallest plans (0.5 GB RAM) work with the swap file in step 2; the plan must include a public **IPv4** address, because internet-wide SSH scanning does not happen over IPv6.

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
adduser --disabled-password cowrie
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

The Cowrie docs page I read does not name the JSON log file. Expect something like `cowrie.json`, and note what it is actually called here, because the stage 8 parser needs the exact name and path.

## 7. Redirect port 22 to Cowrie (from the Cowrie docs)

```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

The docs note this does not apply to loopback, so test from another machine (step 9), not from the server.

Make it survive a reboot **(not from Cowrie docs)**:

```bash
apt-get install iptables-persistent
```

```bash
netfilter-persistent save
```

## 8. Open port 22 to the world

In the Vultr firewall group, change the port 22 rule's source to anywhere (`0.0.0.0/0`). Leave the 22222 rule restricted to `<MY_IP>/32`. Port 2222 never needs to be opened externally.

## 9. Verify from your Mac

Your Mac remembers the real server's host key for port 22; Cowrie presents a different one, so clear the old entry first:

```bash
ssh-keygen -R <IP>
```

```bash
ssh root@<IP>
```

You should land in Cowrie's fake shell (any password may work). Then confirm on the server that the session appears in `var/log/cowrie/`. After that, the box will be found by scanners within hours, and real events start arriving.

## 10. Keeping it alive

`cowrie start` survives logging out but **not a reboot**. Cowrie's docs include a "Running using supervisord" section; use it, or write a systemd unit, so the honeypot restarts with the server. The docs also have an "Updating Cowrie" section. Read both before leaving it for weeks.

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
