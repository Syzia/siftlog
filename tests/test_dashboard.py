"""The local dashboard: its files, its safety properties, the command list and the honeypot check."""
import contextlib
import io
import json
import os
import re
import socketserver
import tempfile
import threading
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from siftlog.api import create_app
from siftlog.api import __main__ as api_main
from siftlog.api.app import DASHBOARD_CSP, STATIC_DIR
from siftlog.api.local import (
    LocalConfig,
    LocalConfigError,
    command_variables,
    commands_markdown,
    load_command_groups,
    load_local_config,
    render_commands,
)
from siftlog.api.probe import CACHE_SECONDS, HoneypotProbe, read_banner
from siftlog.engine import load_rules
from siftlog.store import EventStore

ROOT = os.path.dirname(os.path.dirname(__file__))
RULES_DIR = os.path.join(ROOT, "rules")
TOKEN = "test-token-not-a-real-secret"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
HOST = "192.0.2.10"  # a documentation address: nothing here may ever really connect to it


def static(name):
    with open(os.path.join(STATIC_DIR, name), encoding="utf-8") as fh:
        return fh.read()


class DashboardTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.db = os.path.join(tmp.name, "events.db")
        EventStore(self.db).close()
        self.rules = load_rules(RULES_DIR)

    def client(self, **kwargs):
        return TestClient(create_app(self.db, self.rules, TOKEN, **kwargs))


class StaticFileTests(DashboardTestCase):
    def test_the_page_and_its_files_load_without_a_token(self):
        client = self.client()
        page = client.get("/dashboard/")
        self.assertEqual((page.status_code, page.headers["content-type"]), (200, "text/html; charset=utf-8"))
        self.assertIn("<title>Siftlog</title>", page.text)
        self.assertEqual(client.get("/dashboard/app.js").headers["content-type"].split(";")[0], "text/javascript")
        self.assertEqual(client.get("/dashboard/app.css").headers["content-type"].split(";")[0], "text/css")
        redirect = client.get("/dashboard", follow_redirects=False)
        self.assertEqual((redirect.status_code, redirect.headers["location"].rstrip("/").rsplit("/", 1)[-1]),
                         (307, "dashboard"))

    def test_but_everything_they_display_needs_one(self):
        client = self.client()
        for method, url in (("GET", "/stats"), ("GET", "/alerts"), ("GET", "/commands"),
                            ("GET", "/honeypot"), ("POST", "/honeypot/check")):  # fmt: skip
            with self.subTest(url=url):
                self.assertEqual(client.request(method, url).status_code, 401)

    def test_dashboard_responses_carry_a_strict_content_security_policy(self):
        client = self.client()
        for url in ("/dashboard/", "/dashboard/app.js", "/dashboard/app.css", "/dashboard/missing"):
            with self.subTest(url=url):
                self.assertEqual(client.get(url).headers["content-security-policy"], DASHBOARD_CSP)
        self.assertIn("script-src 'self'", DASHBOARD_CSP)
        self.assertNotIn("unsafe", DASHBOARD_CSP)  # no unsafe-inline, no unsafe-eval
        self.assertEqual(client.get("/health").headers["referrer-policy"], "no-referrer")

    def test_files_outside_the_static_folder_cannot_be_fetched(self):
        client = self.client()
        for url in ("/dashboard/../app.py", "/dashboard/%2e%2e/app.py", "/dashboard/..%2fapp.py",
                    "/dashboard/%2e%2e%2f%2e%2e%2fstore/sqlite.py"):  # fmt: skip
            with self.subTest(url=url):
                response = client.get(url)
                self.assertNotIn("create_app", response.text)
                self.assertNotIn("CREATE TABLE", response.text)
                self.assertIn(response.status_code, (400, 401, 404))


class PageSafetyTests(unittest.TestCase):
    """Log content is attacker-controlled, so how the page handles it is checked here."""

    def test_script_never_parses_data_as_markup_or_code(self):
        script = static("app.js")
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                       "new Function", "srcdoc", 'setAttribute("style"', "javascript:"):  # fmt: skip
            with self.subTest(banned=banned):
                self.assertNotIn(banned, script)
        self.assertIn("createTextNode", script)  # how data reaches the page instead

    def test_every_event_type_has_a_name_on_the_page(self):
        from siftlog import events

        script = static("app.js")
        for name in ("AUTH_FAILURE", "AUTH_SUCCESS", "INVALID_USER", "CONNECTION", "COMMAND", "FILE_TRANSFER"):
            with self.subTest(event_type=name):
                self.assertIn(f'["{getattr(events, name)}", "', script)

    def test_page_has_no_inline_script_style_or_handlers(self):
        page = static("index.html")
        scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", page, flags=re.S)
        self.assertEqual(scripts, [""])  # one script tag, loaded by src, with no inline body
        self.assertIn('<script src="app.js"></script>', page)
        self.assertNotIn("<style", page)
        self.assertIsNone(re.search(r"\sstyle\s*=", page))
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", page))  # onclick= and friends

    def test_nothing_is_loaded_from_another_site(self):
        for name in ("index.html", "app.js", "app.css"):
            with self.subTest(name=name):
                self.assertIsNone(re.search(r"https?://(?!127\.0\.0\.1)", static(name)))

    def test_token_is_taken_from_the_address_fragment_and_removed(self):
        script = static("app.js")
        self.assertIn("location.hash", script)
        self.assertIn("history.replaceState", script)
        self.assertIn("sessionStorage", script)  # this tab only
        self.assertNotIn("localStorage", script)  # not kept once the tab is closed
        self.assertNotIn(TOKEN, "".join(static(n) for n in os.listdir(STATIC_DIR)))


class LocalConfigTests(DashboardTestCase):
    def write(self, data):
        path = os.path.join(self.dir, "siftlog.local.json")
        with open(path, "w") as fh:
            fh.write(data if isinstance(data, str) else json.dumps(data))
        return path

    def test_a_missing_file_means_no_honeypot_configured(self):
        self.assertEqual(load_local_config(os.path.join(self.dir, "none.json")), LocalConfig())
        self.assertEqual(load_local_config(None).honeypot_host, None)

    def test_values_are_read(self):
        config = load_local_config(self.write({"honeypot_host": HOST, "honeypot_port": 2200, "honeypot_key": "~/.ssh/k"}))
        self.assertEqual((config.honeypot_host, config.honeypot_port, config.honeypot_key, config.honeypot_user),
                         (HOST, 2200, "~/.ssh/k", "root"))

    def test_anything_unsafe_to_paste_into_a_shell_is_refused(self):
        bad = [
            {"honeypot_host": "192.0.2.10; rm -rf ~"},
            {"honeypot_host": "$(curl evil)"},
            {"honeypot_host": "a b"},
            {"honeypot_host": ""},
            {"honeypot_key": "~/.ssh/key' ; echo pwned '"},
            {"honeypot_key": "~/.ssh/`whoami`"},
            {"honeypot_logs": "~/logs && rm -rf ~"},
            {"honeypot_dir": "/home/cowrie/$HOME"},
            {"honeypot_user": "root;id"},
            {"honeypot_port": 0},
            {"honeypot_port": 70000},
            {"honeypot_port": "22222"},
            {"honeypot_port": True},
            {"own_addresses": "198.51.100.7"},  # must be a list
            {"own_addresses": ["198.51.100.7; rm -rf ~"]},
            {"own_addresses": ["my-laptop"]},
            {"own_addresses": ["198.51.100.7", 5]},
            {"own_addresses": ["198.51.100.0/99"]},
            {"honeypot_hots": HOST},  # a typo must not be silently ignored
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(LocalConfigError):
                load_local_config(self.write(data))
        for text in ("not json", "[1, 2]", '"just a string"'):
            with self.subTest(text=text), self.assertRaises(LocalConfigError):
                load_local_config(self.write(text))


class CommandTests(DashboardTestCase):
    def commands(self, **kwargs):
        response = self.client(**kwargs).get("/commands", headers=AUTH)
        self.assertEqual(response.status_code, 200, response.text)
        return [command for group in response.json() for command in group["commands"]]

    def test_filled_in_for_this_machine_and_ready_to_paste(self):
        commands = self.commands(local=LocalConfig(honeypot_host=HOST), project_dir="/Users/me/Mini Projects/siftlog")
        self.assertTrue(all(c["ready"] and not c["missing"] for c in commands))
        self.assertFalse(any("{{" in c["command"] or "<" in c["command"].split("'")[0] for c in commands))
        login = next(c for c in commands if c["title"] == "Log in to the honeypot server")
        self.assertEqual(login["command"], f"ssh -i ~/.ssh/honeypot_ed25519 -p 22222 root@{HOST}")
        opener = commands[0]["command"]
        self.assertTrue(opener.startswith('cd "/Users/me/Mini Projects/siftlog" && '))  # quoted: the path has a space
        self.assertIn(f"--db {self.db}", opener)
        self.assertEqual({c["where"] for c in commands}, {"mac", "honeypot"})

    def test_own_addresses_are_put_in_the_honeypot_ingest_command(self):
        title = "2. Parse the logs into the honeypot database"
        plain = next(c for c in self.commands(local=LocalConfig(honeypot_host=HOST), project_dir="/p") if c["title"] == title)
        self.assertEqual(
            plain["command"],
            'cd "/p" && .venv/bin/python -m siftlog.ingest ~/honeypot-logs/cowrie.json* '
            "--source cowrie --db data/honeypot.db --show-ignored",
        )
        path = os.path.join(self.dir, "siftlog.local.json")
        with open(path, "w") as fh:  # written the long way round, to show it is rewritten in standard form
            json.dump({"own_addresses": ["198.51.100.7", "2001:0DB8:0000::/32"]}, fh)
        config = load_local_config(path)
        self.assertEqual(config.own_addresses, ("198.51.100.7", "2001:db8::/32"))
        mine = next(c for c in self.commands(local=config, project_dir="/p") if c["title"] == title)
        self.assertTrue(mine["ready"])
        self.assertTrue(mine["command"].endswith("--show-ignored --ignore-ip 198.51.100.7 --ignore-ip 2001:db8::/32"))

    def test_the_honeypot_data_steps_are_in_order_and_use_their_own_database(self):
        groups = self.client(local=LocalConfig(honeypot_host=HOST), project_dir="/p").get("/commands", headers=AUTH).json()
        steps = next(g for g in groups if g["title"] == "Honeypot data, step by step")["commands"]
        self.assertEqual([c["title"][:2] for c in steps], ["1.", "2.", "3.", "4."])
        self.assertIn("rsync", steps[0]["command"])
        for step in steps[1:]:
            self.assertIn("--db data/honeypot.db", step["command"])  # never mixed into the practice data
            self.assertNotIn(self.db, step["command"])

    def test_commands_run_on_the_mac_all_start_in_the_project_folder(self):
        # A bare relative command fails when the terminal is somewhere else.
        for command in self.commands(local=LocalConfig(honeypot_host=HOST), project_dir="/p"):
            if command["where"] == "mac" and ".venv/bin/python" in command["command"]:
                with self.subTest(title=command["title"]):
                    self.assertTrue(command["command"].startswith('cd "/p" && '))

    def test_without_a_honeypot_address_those_commands_say_so(self):
        commands = self.commands(project_dir="/p")
        not_ready = [c for c in commands if not c["ready"]]
        self.assertEqual({tuple(c["missing"]) for c in not_ready}, {("honeypot_host",)})
        self.assertTrue(all("<HONEYPOT_IP>" in c["command"] for c in not_ready))
        self.assertEqual(len(not_ready), 3)  # log in, watch live, copy logs
        self.assertTrue(next(c for c in commands if c["title"] == "Run the tests")["ready"])

    def test_an_unsafe_project_path_is_never_put_in_a_command(self):
        commands = self.commands(local=LocalConfig(honeypot_host=HOST), project_dir='/tmp/x"; rm -rf ~; echo "')
        self.assertFalse(any("rm -rf" in c["command"] for c in commands))
        self.assertFalse(next(c for c in commands if c["title"] == "Run the tests")["ready"])

    def test_every_placeholder_in_the_command_file_is_known(self):
        variables = command_variables(LocalConfig(), None, "siftlog.db", "rules")
        rendered = render_commands(variables)  # raises KeyError on an unknown {{name}}
        self.assertEqual(sum(len(g["commands"]) for g in rendered), sum(len(g["commands"]) for g in load_command_groups()))
        for group in load_command_groups():
            for command in group["commands"]:
                self.assertIn(command["where"], ("mac", "honeypot"))
                self.assertTrue(command["title"] and command["command"])

    def test_commands_doc_is_generated_from_the_same_file(self):
        with open(os.path.join(ROOT, "docs", "commands.md"), encoding="utf-8") as fh:
            self.assertEqual(
                fh.read(), commands_markdown(),
                "docs/commands.md is out of date: regenerate it with "
                "python -c \"from siftlog.api.local import commands_markdown; "
                "open('docs/commands.md','w').write(commands_markdown())\"",
            )
        self.assertNotRegex(commands_markdown(), r"\b\d{1,3}(\.\d{1,3}){3}\b(?<!203\.0\.113\.77)")  # no real addresses


class Banner(socketserver.BaseRequestHandler):
    reply = b"SSH-2.0-Test_1.0\r\n"

    def handle(self):
        if self.reply:
            self.request.sendall(self.reply)
        else:
            self.request.recv(1)  # say nothing; wait for the client to give up


class ProbeTests(DashboardTestCase):
    def serve(self, reply):
        handler = type("Handler", (Banner,), {"reply": reply})
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_reads_what_a_server_says_it_is(self):
        self.assertEqual(read_banner("127.0.0.1", self.serve(b"SSH-2.0-Test_1.0\r\n")),
                         {"port": mock.ANY, "open": True, "banner": "SSH-2.0-Test_1.0"})

    def test_a_closed_port_and_a_silent_server(self):
        closed = self.serve(b"x")
        # Find a port with nothing listening by asking for one and then not using it.
        import socket

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free = probe.getsockname()[1]
        self.assertEqual(read_banner("127.0.0.1", free, timeout=0.5), {"port": free, "open": False, "banner": ""})
        silent = read_banner("127.0.0.1", self.serve(b""), timeout=0.3)
        self.assertEqual((silent["open"], silent["banner"]), (True, ""))
        self.assertTrue(read_banner("127.0.0.1", closed)["open"])

    def test_a_hostile_banner_is_trimmed_to_plain_text(self):
        port = self.serve(b"SSH-\x1b[31mred\x00\x07" + b"A" * 300 + b"\r\nsecond line\r\n")
        banner = read_banner("127.0.0.1", port)["banner"]
        self.assertLessEqual(len(banner), 80)
        self.assertTrue(banner.isprintable())
        self.assertNotIn("second line", banner)

    def fake(self):
        calls = []

        def reader(host, port):
            calls.append((host, port))
            return {"port": port, "open": True, "banner": f"banner-{port}"}

        return calls, reader

    def test_checks_the_two_ports_of_the_configured_host_only(self):
        calls, reader = self.fake()
        result = HoneypotProbe(HOST, 22222, reader=reader).check()
        self.assertEqual(calls, [(HOST, 22), (HOST, 22222)])
        self.assertEqual([(c["port"], c["role"], c["open"]) for c in result["checks"]],
                         [(22, "honeypot", True), (22222, "admin", True)])
        self.assertEqual((result["configured"], result["host"]), (True, HOST))
        self.assertIsNotNone(result["checked_at"])

    def test_nothing_is_contacted_when_no_honeypot_is_configured(self):
        calls, reader = self.fake()
        probe = HoneypotProbe(None, 22222, reader=reader)
        self.assertEqual(probe.check(), {"configured": False, "host": None, "checked_at": None, "checks": []})
        self.assertEqual(calls, [])

    def test_answers_are_reused_for_a_minute(self):
        # Every check is logged by the honeypot as a visit, so it must not be hammered.
        calls, reader = self.fake()
        clock = [0.0]
        probe = HoneypotProbe(HOST, 22222, reader=reader, clock=lambda: clock[0])
        first = probe.check()
        clock[0] = CACHE_SECONDS - 1
        self.assertEqual(probe.check(), first)
        self.assertEqual(len(calls), 2)  # still only the first pair
        clock[0] = CACHE_SECONDS + 1
        probe.check()
        self.assertEqual(len(calls), 4)

    def test_reading_the_last_result_never_connects(self):
        calls, reader = self.fake()
        probe = HoneypotProbe(HOST, 22222, reader=reader)
        self.assertEqual(probe.last()["checks"], [])
        self.assertEqual(calls, [])
        probe.check()
        self.assertEqual(len(probe.last()["checks"]), 2)
        self.assertEqual(len(calls), 2)

    def test_api_request_cannot_choose_the_target(self):
        calls, reader = self.fake()
        probe = HoneypotProbe(HOST, 22222, reader=reader)
        client = self.client(local=LocalConfig(honeypot_host=HOST), probe=probe)
        self.assertEqual(client.get("/honeypot", headers=AUTH).json()["checks"], [])  # a GET never connects
        self.assertEqual(calls, [])
        response = client.post("/honeypot/check?host=198.51.100.1&port=80", headers=AUTH,
                               json={"host": "198.51.100.1", "port": 80})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(calls, [(HOST, 22), (HOST, 22222)])  # the configured host, whatever was sent
        self.assertEqual(response.json()["host"], HOST)
        self.assertEqual(len(client.get("/honeypot", headers=AUTH).json()["checks"]), 2)


class LauncherTests(DashboardTestCase):
    def build(self, *argv, env=None):
        environment = {k: v for k, v in os.environ.items() if k != api_main.TOKEN_ENV}
        environment.update(env or {})
        err = io.StringIO()
        args = ["--db", self.db, "--rules", RULES_DIR, "--local-config", os.path.join(self.dir, "none.json"), *argv]
        with mock.patch.dict(os.environ, environment, clear=True), contextlib.redirect_stderr(err):
            return api_main.build(args), err.getvalue()

    def test_prints_a_link_that_opens_the_dashboard_signed_in(self):
        server, printed = self.build()
        token = printed.splitlines()[0].rsplit(" ", 1)[-1]
        self.assertEqual(server.signed_in_url, f"http://127.0.0.1:8000/dashboard/#token={token}")
        self.assertIn(server.signed_in_url, printed)
        self.assertFalse(server.open_browser)
        # The token is after the #, which a browser never sends: it is not a query string.
        self.assertNotIn("?", server.signed_in_url)

    def test_a_token_you_chose_is_never_printed_but_the_link_still_works(self):
        server, printed = self.build("--port", "9001", env={api_main.TOKEN_ENV: "my own/token+value"})
        self.assertNotIn("my own", printed)
        self.assertIn("http://127.0.0.1:9001/dashboard/ (sign in with your SIFTLOG_API_TOKEN)", printed)
        self.assertEqual(server.signed_in_url, "http://127.0.0.1:9001/dashboard/#token=my%20own%2Ftoken%2Bvalue")

    def test_open_starts_the_browser_on_the_signed_in_link(self):
        with mock.patch.object(api_main, "build") as build, mock.patch.object(api_main.threading, "Timer") as timer, \
                mock.patch("uvicorn.run") as serve:
            build.return_value = api_main.Server("app", "127.0.0.1", 8000, "http://x/#token=t", True)
            self.assertEqual(api_main.main(["--open"]), 0)
            timer.assert_called_once_with(1.0, api_main.webbrowser.open, ["http://x/#token=t"])
            timer.return_value.start.assert_called_once()
            serve.assert_called_once()
            build.return_value = api_main.Server("app", "127.0.0.1", 8000, "http://x/#token=t", False)
            api_main.main([])
            timer.assert_called_once()  # not again: no browser without --open

    def test_a_broken_local_settings_file_is_a_clear_error(self):
        path = os.path.join(self.dir, "bad.json")
        with open(path, "w") as fh:
            json.dump({"honeypot_host": "x; rm -rf ~"}, fh)
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as stop:
            api_main.build(["--db", self.db, "--rules", RULES_DIR, "--local-config", path])
        self.assertEqual(stop.exception.code, 2)
        self.assertIn("not safe to put in a shell command", err.getvalue())


if __name__ == "__main__":
    unittest.main()
