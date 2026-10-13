import os
import tempfile
import unittest
from datetime import timedelta

from siftlog.engine import EVENT_COUNT, VALUE_COUNT, RuleError, load_rules, parse_rule

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
        self.assertEqual(set(rules), {"ssh-brute-force", "ssh-password-spray", "ssh-credential-stuffing"})
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
