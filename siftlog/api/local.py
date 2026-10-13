"""Machine-specific settings, and the command reference the dashboard shows.

Commands live in one file, ``static/commands.json``, with ``{{name}}``
placeholders. The dashboard fills them with this machine's values, so what it
shows can be pasted as-is. ``docs/commands.md`` is the same list rendered with
neutral placeholders, for when the server is not running.

Personal values (the honeypot's address, key path) come from a git-ignored file,
``siftlog.local.json``, so they never reach the repository.

Every value is checked before it is put into a command. These are commands a
person will paste into a shell, so a value containing quotes, ``;`` or ``$``
must be refused, not interpolated.
"""
import json
import os
import re
from dataclasses import dataclass, fields
from typing import Any, Dict, List, Mapping, Optional

LOCAL_CONFIG = "siftlog.local.json"
COMMANDS_FILE = os.path.join(os.path.dirname(__file__), "static", "commands.json")

_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
_PATH = re.compile(r"^[A-Za-z0-9_./~ -]{1,400}$")  # no quotes, $, `, ;, & or backslashes
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")

MISSING = {  # shown when a value has not been configured
    "honeypot_host": "<HONEYPOT_IP>",
    "project_dir": "<path to the siftlog folder>",
}


class LocalConfigError(ValueError):
    """siftlog.local.json is malformed. The message says how."""


@dataclass(frozen=True)
class LocalConfig:
    honeypot_host: Optional[str] = None  # address of the honeypot server
    honeypot_port: int = 22222  # its admin SSH port (not 22: that is the honeypot itself)
    honeypot_user: str = "root"
    honeypot_key: str = "~/.ssh/honeypot_ed25519"
    honeypot_dir: str = "/home/cowrie/my-honeypot"
    honeypot_logs: str = "~/honeypot-logs"  # where copies of its logs go on this machine


def _check(name: str, value: Any) -> Any:
    if name == "honeypot_port":
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise LocalConfigError(f"{name} must be a port number between 1 and 65535")
        return value
    pattern = {"honeypot_host": _HOST, "honeypot_user": _USER}.get(name, _PATH)
    if not isinstance(value, str) or not pattern.match(value):
        raise LocalConfigError(f"{name} has characters that are not safe to put in a shell command: {value!r}")
    return value


def load_local_config(path: Optional[str]) -> LocalConfig:
    """Read the local settings file. A missing file means defaults, with no honeypot configured."""
    if path is None or not os.path.exists(path):
        return LocalConfig()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise LocalConfigError(f"{path}: cannot be read as JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LocalConfigError(f"{path}: must be a JSON object")
    known = {f.name for f in fields(LocalConfig)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise LocalConfigError(f"{path}: unknown key(s) {', '.join(unknown)}; expected {', '.join(sorted(known))}")
    return LocalConfig(**{name: _check(name, value) for name, value in data.items()})


def command_variables(config: LocalConfig, project_dir: Optional[str], db: str, rules: str) -> Dict[str, Optional[str]]:
    """The values placeholders may use. None means "not known on this machine"."""

    def safe(value: Optional[str]) -> Optional[str]:
        return value if value is not None and _PATH.match(value) else None

    return {
        "project_dir": safe(project_dir),
        "db": safe(db) or "siftlog.db",
        "rules": safe(rules) or "rules",
        "honeypot_host": config.honeypot_host,
        "honeypot_port": str(config.honeypot_port),
        "honeypot_user": config.honeypot_user,
        "honeypot_key": config.honeypot_key,
        "honeypot_dir": config.honeypot_dir,
        "honeypot_logs": config.honeypot_logs,
    }


def load_command_groups() -> List[Dict[str, Any]]:
    with open(COMMANDS_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)["groups"]


def render_commands(variables: Mapping[str, Optional[str]]) -> List[Dict[str, Any]]:
    """Fill the placeholders. A command using a value this machine lacks is marked not ready."""
    rendered = []
    for group in load_command_groups():
        commands = []
        for item in group["commands"]:
            missing: List[str] = []

            def fill(match: "re.Match[str]") -> str:
                name = match.group(1)
                if name not in variables:
                    raise KeyError(f"commands.json uses an unknown placeholder: {name}")
                value = variables[name]
                if value is None:
                    missing.append(name)
                    return MISSING.get(name, f"<{name.upper()}>")
                return value

            commands.append(
                {
                    "title": item["title"],
                    "where": item["where"],
                    "command": _PLACEHOLDER.sub(fill, item["command"]),
                    "note": item.get("note", ""),
                    "ready": not missing,
                    "missing": sorted(set(missing)),
                }
            )
        rendered.append({"title": group["title"], "about": group.get("about", ""), "commands": commands})
    return rendered


def commands_markdown() -> str:
    """The command list as a document, with neutral placeholders instead of personal values."""
    variables = command_variables(LocalConfig(), None, "siftlog.db", "rules")
    where = {"mac": "On your Mac", "honeypot": "On the honeypot (after logging in)"}
    lines = [
        "# Commands",
        "",
        "Every command used to run Siftlog and its honeypot, in one place.",
        "",
        "This page is generated from `siftlog/api/static/commands.json`. The dashboard shows the same list "
        "with this machine's own values filled in, ready to paste. Here, `<path to the siftlog folder>` and "
        "`<HONEYPOT_IP>` stand in for them.",
    ]
    for group in render_commands(variables):
        lines += ["", f"## {group['title']}"]
        if group["about"]:
            lines += ["", group["about"]]
        for command in group["commands"]:
            lines += ["", f"### {command['title']}", "", f"*{where[command['where']]}.*"]
            if command["note"]:
                lines += ["", command["note"]]
            lines += ["", "```bash", command["command"], "```"]
    return "\n".join(lines) + "\n"
