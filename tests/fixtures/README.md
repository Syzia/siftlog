# Fixtures

`sshd_real_format.log` is **hand-written** in the OpenSSH/PAM/rsyslog formats, not captured from a live server. It exists so the parser is not only tested against lines our own simulator generated. All addresses are RFC 5737 / RFC 3849 documentation ranges.

It includes the awkward cases on purpose: a username that looks like the rest of the log line, `message repeated N times`, `sshd-session` (OpenSSH 9.8+), an IPv6 source, PAM chatter, and non-sshd programs.

**TODO (stage 8):** replace or extend it with sanitized lines captured from the honeypot or a real server. Sanitize IPs and usernames before committing, and never commit raw logs (`*.log` is git-ignored except in this directory).
