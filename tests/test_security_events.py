import unittest
from datetime import datetime, timedelta, timezone

from security_events import (
    EventCorrelator,
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

    def test_cloudflare_fallback_id_is_stable(self):
        item = {
            "created_at": "2026-01-01T00:00:00Z",
            "user_email": "a@example.com",
            "ip_address": "203.0.113.2",
        }
        self.assertEqual(cloudflare_event_id(item), cloudflare_event_id(dict(item)))


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


if __name__ == "__main__":
    unittest.main()
