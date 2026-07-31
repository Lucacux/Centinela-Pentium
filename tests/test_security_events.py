import unittest
from datetime import datetime, timedelta, timezone

from security_events import (
    EventCorrelator,
    access_app_matches,
    classify_ssh_origin,
    cloudflare_event_id,
    is_loopback,
    parse_fail2ban_banned,
    parse_fail2ban_jails,
    parse_fail2ban_log,
    parse_ssh_line,
)


class ParserTests(unittest.TestCase):
    def test_parses_ssh_login_ipv4_and_method(self):
        event = parse_ssh_line(
            "sshd[10]: Accepted publickey for luca from 203.0.113.8 port 51200 ssh2"
        )
        self.assertEqual(event["kind"], "ssh_login")
        self.assertEqual(event["user"], "luca")
        self.assertEqual(event["ip"], "203.0.113.8")
        self.assertEqual(event["method"], "publickey")

    def test_parses_invalid_user_failure(self):
        event = parse_ssh_line(
            "sshd[10]: Failed password for invalid user root from 2001:db8::2 port 42 ssh2"
        )
        self.assertEqual(event["kind"], "ssh_fail")
        self.assertEqual(event["user"], "root")
        self.assertEqual(event["ip"], "2001:db8::2")

    def test_parses_pam_authentication_failure(self):
        event = parse_ssh_line(
            "sshd[10]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.3 user=luca"
        )
        self.assertEqual(event["kind"], "ssh_fail")
        self.assertEqual(event["user"], "luca")
        self.assertEqual(event["ip"], "203.0.113.3")

    def test_fail2ban_status_parsers(self):
        self.assertEqual(
            parse_fail2ban_jails("`- Jail list: sshd, recidive"),
            ["sshd", "recidive"],
        )
        self.assertEqual(
            parse_fail2ban_banned("Banned IP list: 203.0.113.2 2001:db8::5"),
            {"203.0.113.2", "2001:db8::5"},
        )

    def test_fail2ban_journal_parser(self):
        event = parse_fail2ban_log(
            "fail2ban.actions: NOTICE [sshd] Ban 203.0.113.19"
        )
        self.assertEqual(
            event,
            {"jail": "sshd", "action": "ban", "ip": "203.0.113.19"},
        )

    def test_loopback_detection(self):
        self.assertTrue(is_loopback("127.0.0.1"))
        self.assertTrue(is_loopback("::1"))
        self.assertFalse(is_loopback("192.168.1.10"))

    def test_uncorrelated_loopback_is_reported_as_proxy_not_external(self):
        origin = classify_ssh_origin(
            "::1", "::1", ["192.168.", "10.", "172."], correlated=False
        )
        self.assertTrue(origin["unresolved_proxy"])
        self.assertFalse(origin["is_local"])
        self.assertIn("Proxy local", origin["label"])

    def test_correlated_proxy_classifies_the_effective_public_ip(self):
        origin = classify_ssh_origin(
            "::1",
            "203.0.113.8",
            ["192.168.", "10.", "172."],
            correlated=True,
        )
        self.assertFalse(origin["unresolved_proxy"])
        self.assertFalse(origin["is_local"])
        self.assertEqual(origin["label"], "⚠️ IP externa")

    def test_direct_lan_login_remains_local(self):
        origin = classify_ssh_origin(
            "192.168.2.10",
            "192.168.2.10",
            ["192.168.", "10.", "172."],
        )
        self.assertTrue(origin["is_local"])
        self.assertEqual(origin["label"], "Red local")

    def test_cloudflare_fallback_id_is_stable(self):
        item = {
            "created_at": "2026-01-01T00:00:00Z",
            "user_email": "a@example.com",
            "ip_address": "203.0.113.2",
        }
        self.assertEqual(cloudflare_event_id(item), cloudflare_event_id(dict(item)))

    def test_access_app_match_is_host_exact_and_path_aware(self):
        self.assertTrue(
            access_app_matches(
                "ssh.example.com", "https://ssh.example.com/private"
            )
        )
        self.assertTrue(
            access_app_matches(
                "https://ssh.example.com/admin",
                "https://ssh.example.com/admin/terminal",
            )
        )
        self.assertFalse(
            access_app_matches(
                "ssh.example.com", "https://ssh.example.com.attacker.test"
            )
        )
        self.assertFalse(
            access_app_matches(
                "ssh.example.com/admin", "ssh.example.com/administrator"
            )
        )


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 7, 30, 20, 0, tzinfo=timezone.utc)
        self.events = EventCorrelator(window_seconds=600)

    def test_summarizes_failures_for_banned_ip(self):
        self.events.add("ssh_fail", ip="203.0.113.9", user="root", timestamp=self.now)
        self.events.add("ssh_fail", ip="203.0.113.9", user="admin", timestamp=self.now)
        summary = self.events.summarize_ip("203.0.113.9", self.now)
        self.assertEqual(summary["ssh_fails"], 2)
        self.assertEqual(summary["users"], ["admin", "root"])

    def test_latest_allowed_cloudflare_event(self):
        self.events.add(
            "cloudflare_access",
            ip="198.51.100.4",
            user="luca@example.com",
            timestamp=self.now - timedelta(seconds=30),
            allowed=True,
            ray_id="abc",
        )
        event = self.events.latest_cloudflare_access(self.now, max_age_seconds=60)
        self.assertEqual(event.ip, "198.51.100.4")
        self.assertEqual(event.metadata["ray_id"], "abc")

    def test_old_cloudflare_event_is_not_correlated(self):
        self.events.add(
            "cloudflare_access",
            timestamp=self.now - timedelta(minutes=4),
            allowed=True,
        )
        self.assertIsNone(
            self.events.latest_cloudflare_access(self.now, max_age_seconds=180)
        )

    def test_selects_nearest_matching_unused_access_event(self):
        self.events.add(
            "cloudflare_access",
            ip="198.51.100.1",
            timestamp=self.now - timedelta(seconds=20),
            allowed=True,
            event_id="other-app",
            app_domain="other.example.com",
        )
        self.events.add(
            "cloudflare_access",
            ip="198.51.100.2",
            timestamp=self.now - timedelta(seconds=10),
            allowed=True,
            event_id="already-used",
            app_domain="ssh.example.com",
        )
        self.events.add(
            "cloudflare_access",
            ip="198.51.100.3",
            timestamp=self.now + timedelta(seconds=2),
            allowed=True,
            event_id="nearest",
            app_domain="https://ssh.example.com",
        )
        event = self.events.nearest_cloudflare_access(
            self.now,
            max_skew_seconds=30,
            app_domain="ssh.example.com",
            excluded_ids={"already-used"},
        )
        self.assertEqual(event.ip, "198.51.100.3")

    def test_nearest_rejects_denied_wrong_action_and_old_events(self):
        self.events.add(
            "cloudflare_access",
            ip="198.51.100.4",
            timestamp=self.now,
            allowed=False,
            event_id="denied",
            app_domain="ssh.example.com",
        )
        self.events.add(
            "cloudflare_access",
            ip="198.51.100.6",
            timestamp=self.now,
            allowed=True,
            action="logout",
            event_id="wrong-action",
            app_domain="ssh.example.com",
        )
        self.events.add(
            "cloudflare_access",
            ip="198.51.100.5",
            timestamp=self.now - timedelta(minutes=4),
            allowed=True,
            event_id="old",
            app_domain="ssh.example.com",
        )
        self.assertIsNone(
            self.events.nearest_cloudflare_access(
                self.now,
                max_skew_seconds=180,
                app_domain="ssh.example.com",
            )
        )


if __name__ == "__main__":
    unittest.main()
