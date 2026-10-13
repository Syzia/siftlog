import ipaddress
import math
import re
import unittest
from datetime import datetime, timezone

import os
import tempfile

from siftlog.simulator import DEFAULT_SCENARIOS, FAKE_GEO, load_labels, simulate, write_files

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
IP_IN_LINE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def haversine_km(a, b):
    lat1, lon1, lat2, lon2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


class SimulatorTests(unittest.TestCase):
    def test_same_seed_is_identical_different_seed_is_not(self):
        a, b, c = simulate(seed=7), simulate(seed=7), simulate(seed=8)
        self.assertEqual((a.lines, a.line_scenarios, a.labels), (b.lines, b.line_scenarios, b.labels))
        self.assertNotEqual(a.lines, c.lines)

    def test_every_line_has_a_scenario_and_every_label_has_lines(self):
        sim = simulate()
        self.assertEqual(len(sim.lines), len(sim.line_scenarios))
        ids = {label.id for label in sim.labels}
        self.assertEqual(ids, {f"{kind}-0" for kind in DEFAULT_SCENARIOS})
        self.assertTrue(ids <= set(sim.line_scenarios))

    def test_low_and_slow_is_an_attack_that_is_not_expected_to_alert(self):
        labels = {l.kind: l for l in simulate().labels}
        self.assertTrue(labels["low_and_slow"].is_attack)
        self.assertFalse(labels["low_and_slow"].expect_alert)
        for kind in ("typo_benign", "nat_office", "legit_travel", "monitor_probe"):
            self.assertFalse(labels[kind].is_attack)
            self.assertFalse(labels[kind].expect_alert)
        for kind in ("brute_force", "password_spray", "credential_stuffing", "impossible_travel"):
            self.assertTrue(labels[kind].expect_alert)
            self.assertIsNotNone(labels[kind].rule_hint)

    def test_an_attack_can_expect_more_than_one_alert(self):
        label = {l.kind: l for l in simulate().labels}["brute_force_success"]
        ip = label.group_key
        self.assertEqual(label.expected_alerts,
                         (("ssh-brute-force", ip), ("ssh-success-after-failures", f"{ip}|ops")))
        plain = {l.kind: l for l in simulate().labels}["brute_force"]
        self.assertEqual(plain.expected_alerts, (("ssh-brute-force", plain.group_key),))

    def test_the_vpn_user_is_benign_and_expects_no_alert(self):
        label = {l.kind: l for l in simulate().labels}["vpn_hop"]
        self.assertEqual((label.is_attack, label.expect_alert, label.expected_alerts), (False, False, ()))
        self.assertIn("false positive", label.note)

    def test_labels_survive_being_written_and_read_back(self):
        sim = simulate(seed=5)
        with tempfile.TemporaryDirectory() as tmp:
            log, labels = os.path.join(tmp, "s.log"), os.path.join(tmp, "s.json")
            write_files(sim, log, labels)
            self.assertEqual(load_labels(labels), sim.labels)

    def test_only_documentation_addresses_appear(self):
        for fmt in ("syslog", "iso"):
            for line in simulate(fmt=fmt).lines:
                # Drop the timestamp so "00:00:00.000000" can't look like an address.
                body = line.split(": ", 1)[1]
                for ip in IP_IN_LINE.findall(body):
                    addr = ipaddress.ip_address(ip)
                    self.assertTrue(any(addr in net for net in DOC_NETS), f"{ip} in {line!r}")

    def test_travel_labels_match_real_geography(self):
        # The "impossible" trip must exceed airliner speed, the legitimate one must not.
        def speed(user_ips, hours):
            a, b = (FAKE_GEO[ip] for ip in user_ips)
            return haversine_km(a, b) / hours

        self.assertGreater(speed(("198.51.100.10", "203.0.113.50"), 25 / 60), 900)
        self.assertLess(speed(("198.51.100.10", "198.51.100.20"), 14), 900)

    def test_start_must_be_utc(self):
        with self.assertRaises(ValueError):
            simulate(start=datetime(2026, 1, 1))
        with self.assertRaises(ValueError):
            simulate(scenarios={"nope": 1})

    def test_multiple_instances_get_distinct_ids_and_addresses(self):
        sim = simulate(scenarios={"brute_force": 3})
        self.assertEqual([l.id for l in sim.labels], ["brute_force-0", "brute_force-1", "brute_force-2"])
        self.assertEqual(len({l.group_key for l in sim.labels}), 3)

    def test_window_crossing_new_year(self):
        sim = simulate(start=datetime(2026, 12, 31, 20, tzinfo=timezone.utc), fmt="iso")
        self.assertTrue(any(l.startswith("2027-") for l in sim.lines))


if __name__ == "__main__":
    unittest.main()
