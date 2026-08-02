import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from security_events import SshKeyDirectory
from ssh_baseline import (
    CRITICAL,
    INFO,
    WARNING,
    LoginBaseline,
    is_private,
    source_group,
)


AT = datetime(2026, 8, 2, 20, 50, tzinfo=timezone.utc)


def login(**overrides):
    event = {
        "user": "luca",
        "ip": "192.168.2.40",
        "method": "publickey",
        "fingerprint": "SHA256:ansible",
    }
    event.update(overrides)
    return event


def directory(**kwargs):
    entries = kwargs.pop("entries", [
        {"fingerprint": "SHA256:ansible", "comment": "ansible", "user": "luca"},
    ])
    covered = kwargs.pop("covered_users", ["luca", "root"])
    return SshKeyDirectory().load(entries, covered_users=covered)


class SourceGroupTests(unittest.TestCase):
    def test_same_lan_addresses_share_a_group(self):
        """DHCP mueve la IP dentro de la LAN; eso no es un origen nuevo."""
        self.assertEqual(
            source_group("192.168.2.40"), source_group("192.168.2.77")
        )

    def test_different_subnets_do_not_share_a_group(self):
        self.assertNotEqual(
            source_group("192.168.2.40"), source_group("192.168.1.70")
        )

    def test_loopback_is_its_own_group(self):
        self.assertEqual(source_group("127.0.0.1"), "loopback")
        self.assertEqual(source_group("::1"), "loopback")

    def test_private_detection(self):
        self.assertTrue(is_private("192.168.2.40"))
        self.assertFalse(is_private("203.0.113.9"))


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.baseline = LoginBaseline(min_observations=3)

    def train(self, count=5, **overrides):
        for index in range(count):
            self.baseline.observe(
                "mbp", login(**overrides), now=AT + timedelta(days=index)
            )

    def test_first_login_for_a_key_is_reported(self):
        verdict = self.baseline.assess("mbp", login(), directory(), now=AT)
        self.assertTrue(verdict.suspicious)
        self.assertIn("Primer login", verdict.texts[0])

    def test_known_routine_login_is_silent(self):
        self.train()
        verdict = self.baseline.assess(
            "mbp", login(), directory(), now=AT + timedelta(days=6)
        )
        self.assertFalse(verdict.suspicious)
        self.assertEqual(verdict.reasons, [])

    def test_unknown_fingerprint_is_critical(self):
        verdict = self.baseline.assess(
            "mbp", login(fingerprint="SHA256:intruso"), directory(), now=AT
        )
        self.assertEqual(verdict.severity, CRITICAL)
        self.assertTrue(
            any("no figura" in text for text in verdict.texts), verdict.texts
        )

    def test_unreadable_keyring_does_not_accuse_the_key(self):
        """root sin authorized_keys legible: no verificable, no desconocida."""
        verdict = self.baseline.assess(
            "mbp",
            login(user="root", fingerprint="SHA256:dokploy"),
            directory(covered_users=["luca"]),
            now=AT,
        )
        self.assertFalse(
            any("no figura" in text for text in verdict.texts), verdict.texts
        )
        self.assertTrue(
            any("no es verificable" in text for text in verdict.texts),
            verdict.texts,
        )

    def test_password_auth_is_critical_even_for_the_owner(self):
        verdict = self.baseline.assess(
            "mbp", login(method="password", fingerprint=""), directory(), now=AT
        )
        self.assertEqual(verdict.severity, CRITICAL)
        self.assertTrue(any("password" in text for text in verdict.texts))

    def test_key_authorized_for_another_user_is_critical(self):
        verdict = self.baseline.assess(
            "mbp", login(user="root"), directory(), now=AT
        )
        self.assertEqual(verdict.severity, CRITICAL)
        self.assertTrue(
            any("entro como" in text for text in verdict.texts), verdict.texts
        )

    def test_new_subnet_is_flagged_once_the_profile_is_established(self):
        self.train()
        verdict = self.baseline.assess(
            "mbp",
            login(ip="192.168.1.70"),
            directory(),
            now=AT + timedelta(days=6),
        )
        self.assertEqual(verdict.severity, WARNING)
        self.assertTrue(any("subred nueva" in text for text in verdict.texts))

    def test_new_external_ip_outranks_a_new_subnet(self):
        self.train()
        verdict = self.baseline.assess(
            "mbp",
            login(ip="203.0.113.9"),
            directory(),
            now=AT + timedelta(days=6),
        )
        self.assertEqual(verdict.severity, CRITICAL)
        self.assertTrue(any("IP externa nueva" in text for text in verdict.texts))

    def test_young_profile_does_not_produce_anomalies(self):
        """Con dos logins previos todavia no se sabe que es normal."""
        self.train(count=2)
        verdict = self.baseline.assess(
            "mbp",
            login(ip="203.0.113.9"),
            directory(),
            now=AT + timedelta(days=3),
        )
        self.assertFalse(verdict.suspicious)

    def test_scheduled_key_outside_its_window_is_flagged(self):
        self.train()
        verdict = self.baseline.assess(
            "mbp", login(), directory(), now=AT + timedelta(days=6, hours=7)
        )
        self.assertTrue(
            any("agenda habitual" in text for text in verdict.texts),
            verdict.texts,
        )

    def test_interactive_key_at_any_hour_is_not_flagged(self):
        """Una clave sin agenda no puede violar una agenda que no tiene."""
        for index, hour in enumerate([1, 6, 9, 13, 17, 21, 23]):
            self.baseline.observe(
                "mbp",
                login(),
                now=AT.replace(hour=hour) + timedelta(days=index),
            )
        verdict = self.baseline.assess(
            "mbp", login(), directory(), now=AT.replace(hour=4) + timedelta(days=9)
        )
        self.assertFalse(
            any("agenda habitual" in text for text in verdict.texts),
            verdict.texts,
        )

    def test_assess_does_not_mutate_the_profile(self):
        self.train()
        before = dict(self.baseline.profile("mbp", "SHA256:ansible", "luca"))
        self.baseline.assess("mbp", login(), directory(), now=AT)
        after = self.baseline.profile("mbp", "SHA256:ansible", "luca")
        self.assertEqual(before["count"], after["count"])

    def test_info_alone_is_not_suspicion(self):
        verdict = self.baseline.assess(
            "mbp",
            login(user="root", fingerprint="SHA256:dokploy"),
            directory(covered_users=["luca"]),
            now=AT,
        )
        informational = [
            reason for reason in verdict.reasons if reason["severity"] == INFO
        ]
        self.assertTrue(informational)


class PersistenceTests(unittest.TestCase):
    def test_profiles_survive_a_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "nested", "baseline.json")
            first = LoginBaseline(path).load()
            for index in range(5):
                first.observe("mbp", login(), now=AT + timedelta(days=index))
            self.assertTrue(first.save())

            second = LoginBaseline(path).load()
            profile = second.profile("mbp", "SHA256:ansible", "luca")
            self.assertIsNotNone(profile)
            self.assertEqual(profile["count"], 5)

    def test_corrupt_state_does_not_raise(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "baseline.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{no es json")
            baseline = LoginBaseline(path).load()
            self.assertEqual(baseline.profiles, {})

    def test_saved_file_is_not_world_readable(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "baseline.json")
            baseline = LoginBaseline(path).load()
            baseline.observe("mbp", login(), now=AT)
            baseline.save()
            self.assertEqual(os.stat(path).st_mode & 0o077, 0)

    def test_prune_drops_profiles_past_retention(self):
        baseline = LoginBaseline()
        baseline.observe("mbp", login(), now=AT - timedelta(days=400))
        baseline.observe("mbp", login(user="otro"), now=AT)
        self.assertEqual(baseline.prune(now=AT), 1)
        self.assertIsNotNone(baseline.profile("mbp", "SHA256:ansible", "otro"))

    def test_disabled_baseline_writes_nothing(self):
        baseline = LoginBaseline("").load()
        baseline.observe("mbp", login(), now=AT)
        self.assertFalse(baseline.save())


if __name__ == "__main__":
    unittest.main()
