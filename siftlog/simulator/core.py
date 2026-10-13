"""Seeded generator of SSH auth logs with ground-truth labels.

Every generated line is tagged with the scenario that produced it, so detection
rules can later be scored for precision and recall instead of eyeballed.

Attack scenarios
    brute_force          one IP hammering root/admin; should fire ssh-brute-force
    password_spray       one IP, 30 distinct users, paced to stay under the
                         per-IP brute-force threshold; should fire ssh-password-spray
    credential_stuffing  25 IPs, 1-3 attempts each, one host; should fire
                         ssh-credential-stuffing (grouped by host, not by IP)
    impossible_travel    two successes for one user from London and Sydney 25
                         minutes apart; should fire ssh-impossible-travel
    low_and_slow         one failure every ~2.5 minutes for 6 hours. A real attack
                         that stays under default thresholds: expect_alert is
                         False and it is a documented miss, not a bug.
    brute_force_success  25 failures against one account, then a successful login.
                         Should fire two rules: ssh-brute-force (keyed on the
                         address) and ssh-success-after-failures (address + user).

Benign scenarios (must produce no alert)
    typo_benign          a user mistypes a password 1-3 times, then succeeds
    nat_office           15 real users behind one NAT'd IP, 6 of them with a typo
    legit_travel         London login, then New York 14 hours later
    monitor_probe        a monitoring check failing publickey once a minute
    vpn_hop              a real user logs in from London, then ten minutes later
                         through a VPN exit in New York. Benign, but by location
                         alone it is indistinguishable from stolen credentials, so
                         ssh-impossible-travel fires. A documented FALSE POSITIVE:
                         the mirror image of low_and_slow.

Only RFC 5737 documentation addresses are used, so no real IP can leak into a
fixture. Output is always UTC.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Mapping, Optional, Tuple

from siftlog.simulator.geo import LONDON_IP, NEW_YORK_IP, OFFICE_IP, SYDNEY_IP

HOST = "bastion01"
BACKGROUND = "background"

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

_OFFICE_USERS = (
    "frank", "grace", "heidi", "ivan", "judy", "ken", "liam", "mona",
    "nick", "olga", "pat", "quinn", "rosa", "sam", "tina",
)  # fmt: skip
_BASELINE_USERS = ("dave", "erin", "deploy", "svc-backup")
VALID_USERS = frozenset(
    {"root", "alice", "bob", "carol", "nagios", "ops", "vera"} | set(_OFFICE_USERS) | set(_BASELINE_USERS)
)

# Names scanners try. None of these are valid accounts on the simulated host.
_DICTIONARY = (
    "admin", "administrator", "test", "test1", "guest", "user", "oracle", "postgres",
    "mysql", "git", "ftp", "ftpuser", "www", "www-data", "nginx", "apache", "tomcat",
    "jenkins", "ubuntu", "debian", "centos", "pi", "vagrant", "ansible", "hadoop",
    "elastic", "kafka", "redis", "minio", "backup", "support", "info", "mail",
    "postmaster", "dev", "staging", "demo", "operator", "default", "service",
)  # fmt: skip

# Addresses with fixed roles (see geo.py), excluded from the random pools.
_RESERVED_ATTACKER_HOSTS = {50}
_RESERVED_BENIGN_HOSTS = {10, 20, 99}
_MONITOR_IP = "198.51.100.99"


@dataclass(frozen=True)
class ScenarioLabel:
    id: str
    kind: str
    is_attack: bool
    # Whether a correctly tuned rule set should alert. False for benign traffic
    # and for attacks that are a documented miss (low_and_slow).
    expect_alert: bool
    group_key: Optional[str]  # what an alert for this scenario should be keyed on
    rule_hint: Optional[str]  # the rule id expected to fire
    start: datetime
    end: datetime
    note: str = ""
    # Further (rule id, group key) alerts this scenario should raise, when one
    # attack is expected to trip more than one rule.
    also_expected: Tuple[Tuple[str, str], ...] = ()

    @property
    def expected_alerts(self) -> Tuple[Tuple[str, str], ...]:
        """Every (rule id, group key) a correct rule set should raise for this scenario."""
        if not self.expect_alert or self.rule_hint is None or self.group_key is None:
            return ()
        return ((self.rule_hint, self.group_key),) + self.also_expected

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "is_attack": self.is_attack,
            "expect_alert": self.expect_alert,
            "group_key": self.group_key,
            "rule_hint": self.rule_hint,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "note": self.note,
            "also_expected": [list(pair) for pair in self.also_expected],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "ScenarioLabel":
        return cls(
            id=str(data["id"]),
            kind=str(data["kind"]),
            is_attack=bool(data["is_attack"]),
            expect_alert=bool(data["expect_alert"]),
            group_key=None if data.get("group_key") is None else str(data["group_key"]),
            rule_hint=None if data.get("rule_hint") is None else str(data["rule_hint"]),
            start=datetime.fromisoformat(str(data["start"])),
            end=datetime.fromisoformat(str(data["end"])),
            note=str(data.get("note", "")),
            also_expected=tuple((str(r), str(k)) for r, k in data.get("also_expected", ())),  # type: ignore[union-attr]
        )


@dataclass
class SimulatedLog:
    lines: List[str]
    line_scenarios: List[str]  # scenario id for each line; BACKGROUND for baseline
    labels: List[ScenarioLabel]
    seed: int
    fmt: str


@dataclass(frozen=True)
class _Rec:
    ts: datetime
    pid: int
    message: str


@dataclass
class _Result:
    recs: List[_Rec]
    group_key: Optional[str]
    rule_hint: Optional[str]
    is_attack: bool
    expect_alert: bool
    note: str = ""
    also_expected: Tuple[Tuple[str, str], ...] = ()


class _Ctx:
    """Shared RNG and address pools, so scenarios never reuse each other's IPs."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self._attackers = [n for n in range(1, 255) if n not in _RESERVED_ATTACKER_HOSTS]
        self._benign = [n for n in range(1, 255) if n not in _RESERVED_BENIGN_HOSTS]
        rng.shuffle(self._attackers)
        rng.shuffle(self._benign)

    def attacker_ip(self) -> str:
        return f"203.0.113.{self._attackers.pop()}"  # TEST-NET-3

    def benign_ip(self) -> str:
        return f"198.51.100.{self._benign.pop()}"  # TEST-NET-2

    def pid(self) -> int:
        return self.rng.randint(1000, 32000)

    def port(self) -> int:
        return self.rng.randint(32768, 60999)

    def fingerprint(self) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return "SHA256:" + "".join(self.rng.choice(alphabet) for _ in range(43))


def _secs(n: float) -> timedelta:
    return timedelta(seconds=n)


def _failed_attempt(ctx: _Ctx, ts: datetime, ip: str, user: str, method: str = "password") -> List[_Rec]:
    """One failed login, rendered the way OpenSSH + PAM log it."""
    pid, port = ctx.pid(), ctx.port()
    valid = user in VALID_USERS
    recs: List[_Rec] = []
    if not valid:
        recs += [
            _Rec(ts, pid, f"Invalid user {user} from {ip} port {port}"),
            _Rec(ts, pid, "pam_unix(sshd:auth): check pass; user unknown"),
            _Rec(
                ts, pid,
                f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} ",
            ),
            _Rec(ts + _secs(1), pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2"),
            _Rec(ts + _secs(2), pid, f"Connection closed by invalid user {user} {ip} port {port} [preauth]"),
        ]  # fmt: skip
    elif method == "publickey":
        recs += [
            _Rec(ts, pid, f"Failed publickey for {user} from {ip} port {port} ssh2: RSA {ctx.fingerprint()}"),
            _Rec(ts + _secs(1), pid, f"Connection closed by authenticating user {user} {ip} port {port} [preauth]"),
        ]
    else:
        recs += [
            _Rec(
                ts, pid,
                f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}",
            ),
            _Rec(ts + _secs(1), pid, f"Failed password for {user} from {ip} port {port} ssh2"),
            _Rec(ts + _secs(2), pid, f"Connection closed by authenticating user {user} {ip} port {port} [preauth]"),
        ]  # fmt: skip
    return recs


def _success_login(ctx: _Ctx, ts: datetime, ip: str, user: str, method: str = "password") -> List[_Rec]:
    pid, port = ctx.pid(), ctx.port()
    tail = f": RSA {ctx.fingerprint()}" if method == "publickey" else ""
    session_end = ts + _secs(ctx.rng.randint(300, 3600))
    return [
        _Rec(ts, pid, f"Accepted {method} for {user} from {ip} port {port} ssh2{tail}"),
        _Rec(ts, pid, f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)"),
        _Rec(session_end, pid, f"Disconnected from user {user} {ip} port {port}"),
        _Rec(session_end, pid, f"pam_unix(sshd:session): session closed for user {user}"),
    ]


# --- attack scenarios -------------------------------------------------------


def _brute_force(ctx: _Ctx, t0: datetime) -> _Result:
    ip = ctx.attacker_ip()
    recs: List[_Rec] = []
    t = t0
    for _ in range(40):
        recs += _failed_attempt(ctx, t, ip, ctx.rng.choice(("root", "admin", "ubuntu")))
        t += _secs(ctx.rng.randint(1, 4))
    return _Result(recs, ip, "ssh-brute-force", is_attack=True, expect_alert=True)


def _password_spray(ctx: _Ctx, t0: datetime) -> _Result:
    ip = ctx.attacker_ip()
    users = ["root"] + ctx.rng.sample(_DICTIONARY, 29)
    recs: List[_Rec] = []
    t = t0
    for user in users:
        recs += _failed_attempt(ctx, t, ip, user)
        # 40-60 s apart keeps the per-IP rate under the brute-force threshold.
        t += _secs(ctx.rng.randint(40, 60))
    return _Result(recs, ip, "ssh-password-spray", is_attack=True, expect_alert=True)


def _credential_stuffing(ctx: _Ctx, t0: datetime) -> _Result:
    recs: List[_Rec] = []
    for _ in range(25):
        ip = ctx.attacker_ip()
        t = t0 + _secs(ctx.rng.randint(0, 480))
        for user in ctx.rng.sample(_DICTIONARY + tuple(sorted(_BASELINE_USERS)), ctx.rng.randint(1, 3)):
            recs += _failed_attempt(ctx, t, ip, user)
            t += _secs(ctx.rng.randint(5, 20))
    return _Result(
        recs, HOST, "ssh-credential-stuffing", is_attack=True, expect_alert=True,
        note="no single IP is loud; the signal is many distinct IPs against one host",
    )  # fmt: skip


def _impossible_travel(ctx: _Ctx, t0: datetime) -> _Result:
    recs = _success_login(ctx, t0, LONDON_IP, "carol")
    recs += _success_login(ctx, t0 + timedelta(minutes=25), SYDNEY_IP, "carol")
    return _Result(recs, "carol", "ssh-impossible-travel", is_attack=True, expect_alert=True)


def _low_and_slow(ctx: _Ctx, t0: datetime) -> _Result:
    ip = ctx.attacker_ip()
    recs: List[_Rec] = []
    t = t0
    for i in range(144):
        recs += _failed_attempt(ctx, t, ip, ("root", "admin")[i % 2])
        t += _secs(150 + ctx.rng.randint(-20, 20))
    return _Result(
        recs, ip, None, is_attack=True, expect_alert=False,
        note="evades default thresholds by design; documented miss",
    )  # fmt: skip


def _brute_force_success(ctx: _Ctx, t0: datetime) -> _Result:
    ip = ctx.attacker_ip()
    recs: List[_Rec] = []
    t = t0
    for _ in range(25):
        recs += _failed_attempt(ctx, t, ip, "ops")
        t += _secs(ctx.rng.randint(1, 4))
    recs += _success_login(ctx, t, ip, "ops")
    return _Result(
        recs, ip, "ssh-brute-force", is_attack=True, expect_alert=True,
        note="the guess worked: the login after the failures is the alert that matters",
        also_expected=(("ssh-success-after-failures", f"{ip}|ops"),),
    )  # fmt: skip


# --- benign scenarios -------------------------------------------------------


def _typo_benign(ctx: _Ctx, t0: datetime) -> _Result:
    ip = ctx.benign_ip()
    recs: List[_Rec] = []
    t = t0
    for _ in range(ctx.rng.randint(1, 3)):
        recs += _failed_attempt(ctx, t, ip, "alice")
        t += _secs(ctx.rng.randint(5, 12))
    recs += _success_login(ctx, t, ip, "alice")
    return _Result(recs, ip, None, is_attack=False, expect_alert=False)


def _nat_office(ctx: _Ctx, t0: datetime) -> _Result:
    recs: List[_Rec] = []
    typo_users = set(ctx.rng.sample(_OFFICE_USERS, 6))
    offsets = sorted(ctx.rng.randint(0, 1800) for _ in _OFFICE_USERS)
    for user, offset in zip(_OFFICE_USERS, offsets):
        t = t0 + _secs(offset)
        if user in typo_users:
            recs += _failed_attempt(ctx, t, OFFICE_IP, user)
            t += _secs(ctx.rng.randint(5, 15))
        recs += _success_login(ctx, t, OFFICE_IP, user)
    return _Result(recs, OFFICE_IP, None, is_attack=False, expect_alert=False,
                   note="many distinct users from one IP, all legitimate")  # fmt: skip


def _legit_travel(ctx: _Ctx, t0: datetime) -> _Result:
    recs = _success_login(ctx, t0, LONDON_IP, "bob")
    recs += _success_login(ctx, t0 + timedelta(hours=14), NEW_YORK_IP, "bob")
    return _Result(recs, "bob", None, is_attack=False, expect_alert=False,
                   note="London to New York in 14h is a normal flight")  # fmt: skip


def _monitor_probe(ctx: _Ctx, t0: datetime) -> _Result:
    recs: List[_Rec] = []
    for i in range(120):
        recs += _failed_attempt(ctx, t0 + _secs(60 * i), _MONITOR_IP, "nagios", method="publickey")
    return _Result(recs, _MONITOR_IP, None, is_attack=False, expect_alert=False,
                   note="five failures per five minutes, never near the threshold")  # fmt: skip


def _vpn_hop(ctx: _Ctx, t0: datetime) -> _Result:
    recs = _success_login(ctx, t0, LONDON_IP, "vera")
    recs += _success_login(ctx, t0 + timedelta(minutes=10), NEW_YORK_IP, "vera")
    return _Result(recs, "vera", None, is_attack=False, expect_alert=False,
                   note="documented false positive: a VPN makes a real user appear to teleport")  # fmt: skip


_SCENARIOS: Dict[str, Callable[[_Ctx, datetime], _Result]] = {
    "brute_force": _brute_force,
    "password_spray": _password_spray,
    "credential_stuffing": _credential_stuffing,
    "impossible_travel": _impossible_travel,
    "low_and_slow": _low_and_slow,
    "typo_benign": _typo_benign,
    "nat_office": _nat_office,
    "legit_travel": _legit_travel,
    "monitor_probe": _monitor_probe,
    # Added in stage 4. Kept last so the scenarios above generate exactly as before.
    "brute_force_success": _brute_force_success,
    "vpn_hop": _vpn_hop,
}
DEFAULT_SCENARIOS: Mapping[str, int] = {kind: 1 for kind in _SCENARIOS}


def simulate(
    seed: int = 1234,
    scenarios: Optional[Mapping[str, int]] = None,
    start: Optional[datetime] = None,
    duration_hours: float = 48,
    fmt: str = "syslog",
    baseline_logins: int = 40,
) -> SimulatedLog:
    """Generate a deterministic log. Same arguments always give the same output.

    ``scenarios`` maps kind -> number of instances. Each instance starts at a
    random point in the first half of the window so the longest scenarios (the
    6-hour low_and_slow, the 14-hour travel gap) still fit inside it.
    """
    if fmt not in ("syslog", "iso"):
        raise ValueError(f"fmt must be 'syslog' or 'iso', not {fmt!r}")
    plan = dict(DEFAULT_SCENARIOS if scenarios is None else scenarios)
    unknown = sorted(set(plan) - set(_SCENARIOS))
    if unknown:
        raise ValueError(f"unknown scenario kinds: {unknown}")
    start = start or datetime(2026, 3, 1, tzinfo=timezone.utc)
    if start.tzinfo is None or start.utcoffset() != timedelta(0):
        raise ValueError("start must be timezone-aware UTC")

    rng = random.Random(seed)
    ctx = _Ctx(rng)
    horizon = int(duration_hours * 3600)

    tagged: List[Tuple[datetime, int, str, _Rec]] = []
    labels: List[ScenarioLabel] = []

    def add(scenario_id: str, recs: List[_Rec]) -> None:
        for rec in recs:
            tagged.append((rec.ts, len(tagged), scenario_id, rec))

    for kind in _SCENARIOS:  # registry order, so output doesn't depend on dict order
        for n in range(plan.get(kind, 0)):
            scenario_id = f"{kind}-{n}"
            result = _SCENARIOS[kind](ctx, start + _secs(rng.randint(0, horizon // 2)))
            add(scenario_id, result.recs)
            labels.append(
                ScenarioLabel(
                    id=scenario_id,
                    kind=kind,
                    is_attack=result.is_attack,
                    expect_alert=result.expect_alert,
                    group_key=result.group_key,
                    rule_hint=result.rule_hint,
                    start=min(r.ts for r in result.recs),
                    end=max(r.ts for r in result.recs),
                    note=result.note,
                    also_expected=result.also_expected,
                )
            )

    home_ip = {user: ctx.benign_ip() for user in _BASELINE_USERS}
    for _ in range(baseline_logins):
        user = rng.choice(_BASELINE_USERS)
        method = "publickey" if user in ("deploy", "svc-backup") else "password"
        add(BACKGROUND, _success_login(ctx, start + _secs(rng.randint(0, horizon)), home_ip[user], user, method))

    tagged.sort(key=lambda item: (item[0], item[1]))
    return SimulatedLog(
        lines=[_render(rec, fmt) for _, _, _, rec in tagged],
        line_scenarios=[scenario_id for _, _, scenario_id, _ in tagged],
        labels=labels,
        seed=seed,
        fmt=fmt,
    )


def _render(rec: _Rec, fmt: str) -> str:
    ts = rec.ts
    if fmt == "syslog":
        stamp = f"{_MONTHS[ts.month - 1]} {ts.day:>2} {ts:%H:%M:%S}"  # no year, as in real syslog
    else:
        stamp = f"{ts:%Y-%m-%dT%H:%M:%S}.{ts.microsecond:06d}+00:00"
    return f"{stamp} {HOST} sshd[{rec.pid}]: {rec.message}"


def write_files(sim: SimulatedLog, log_path: str, labels_path: str) -> None:
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sim.lines) + "\n")
    payload = {
        "seed": sim.seed,
        "format": sim.fmt,
        "scenarios": [label.to_dict() for label in sim.labels],
        "line_scenarios": sim.line_scenarios,
    }
    with open(labels_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def load_labels(labels_path: str) -> List[ScenarioLabel]:
    """Read the scenario labels back from a file written by write_files()."""
    with open(labels_path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    return [ScenarioLabel.from_dict(item) for item in payload["scenarios"]]
