"""Security event parsing, correlation and Cloudflare Access log retrieval.

The Discord-specific presentation stays in ``main.py``.  Keeping parsing and
correlation here makes the sensitive parts deterministic and unit-testable.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import re

import aiohttp


_SSH_LOGIN_RE = re.compile(
    r"\bAccepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)
_SSH_FAIL_RE = re.compile(
    r"\bFailed\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<port>\d+))?"
)
_SSH_PAM_FAIL_RE = re.compile(
    r"\bauthentication failure;.*\brhost=(?P<ip>[0-9a-fA-F:.]+)"
    r"(?:\s+user=(?P<user>\S+))?"
)
_JAILS_RE = re.compile(r"Jail list:\s*(?P<jails>.*)$", re.MULTILINE)
_BANNED_RE = re.compile(r"Banned IP list:\s*(?P<ips>.*)$", re.MULTILINE)
_FAIL2BAN_LOG_RE = re.compile(
    r"\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban)\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)"
)


def utcnow():
    return datetime.now(timezone.utc)


def parse_timestamp(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return utcnow()
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return utcnow()


def is_loopback(value):
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value in {"localhost", "::ffff:127.0.0.1"}


def parse_ssh_line(line):
    """Return a normalized SSH event dict, or ``None`` for unrelated lines."""
    match = _SSH_LOGIN_RE.search(line)
    if match:
        return {"kind": "ssh_login", **match.groupdict()}
    match = _SSH_FAIL_RE.search(line)
    if match:
        return {"kind": "ssh_fail", **match.groupdict()}
    match = _SSH_PAM_FAIL_RE.search(line)
    if match:
        values = match.groupdict()
        return {
            "kind": "ssh_fail",
            "user": values.get("user") or "desconocido",
            "ip": values["ip"],
            "port": None,
        }
    return None


def parse_fail2ban_jails(output):
    match = _JAILS_RE.search(output or "")
    if not match:
        return []
    return [item.strip() for item in match.group("jails").split(",") if item.strip()]


def parse_fail2ban_banned(output):
    match = _BANNED_RE.search(output or "")
    if not match:
        return set()
    return {item for item in match.group("ips").split() if item}


def parse_fail2ban_log(line):
    match = _FAIL2BAN_LOG_RE.search(line or "")
    if not match:
        return None
    event = match.groupdict()
    event["action"] = event["action"].lower()
    return event


@dataclass(frozen=True)
class SecurityEvent:
    kind: str
    timestamp: datetime
    ip: str = ""
    user: str = ""
    metadata: dict = field(default_factory=dict)


class EventCorrelator:
    """Bounded in-memory timeline used to enrich alerts across data sources."""

    def __init__(self, window_seconds=600, max_events=2000):
        self.window = timedelta(seconds=window_seconds)
        self.events = deque(maxlen=max_events)

    def add(self, kind, ip="", user="", timestamp=None, **metadata):
        event = SecurityEvent(
            kind=kind,
            timestamp=parse_timestamp(timestamp),
            ip=ip or "",
            user=user or "",
            metadata=metadata,
        )
        self.events.append(event)
        self.prune(event.timestamp)
        return event

    def prune(self, now=None):
        now = parse_timestamp(now)
        cutoff = now - self.window
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def recent(self, *, kind=None, ip=None, now=None, max_age_seconds=None):
        now = parse_timestamp(now)
        cutoff = now - (
            timedelta(seconds=max_age_seconds)
            if max_age_seconds is not None
            else self.window
        )
        return [
            event
            for event in self.events
            if event.timestamp >= cutoff
            and (kind is None or event.kind == kind)
            and (ip is None or event.ip == ip)
        ]

    def summarize_ip(self, ip, now=None, max_age_seconds=None):
        events = self.recent(
            ip=ip, now=now, max_age_seconds=max_age_seconds
        )
        fails = [event for event in events if event.kind == "ssh_fail"]
        users = sorted({event.user for event in events if event.user})
        return {
            "events": len(events),
            "ssh_fails": len(fails),
            "users": users,
            "first_seen": min((event.timestamp for event in events), default=None),
            "last_seen": max((event.timestamp for event in events), default=None),
        }

    def latest_cloudflare_access(self, now=None, max_age_seconds=180):
        allowed = [
            event
            for event in self.recent(
                kind="cloudflare_access",
                now=now,
                max_age_seconds=max_age_seconds,
            )
            if event.metadata.get("allowed")
        ]
        return max(allowed, key=lambda event: event.timestamp, default=None)


class CloudflareAccessClient:
    """Minimal read-only client for Zero Trust Access authentication logs."""

    API = "https://api.cloudflare.com/client/v4"

    def __init__(self, account_id, token, timeout=20):
        self.account_id = account_id
        self._headers = {"Authorization": f"Bearer {token}"}
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    async def fetch(self, since, limit=100):
        params = {
            "since": parse_timestamp(since).isoformat().replace("+00:00", "Z"),
            "direction": "asc",
            "limit": str(limit),
        }
        url = (
            f"{self.API}/accounts/{self.account_id}"
            "/access/logs/access_requests"
        )
        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            async with session.get(url, headers=self._headers, params=params) as response:
                payload = await response.json(content_type=None)
                if response.status != 200 or not payload.get("success"):
                    errors = payload.get("errors") or []
                    detail = errors[0].get("message") if errors else f"HTTP {response.status}"
                    raise RuntimeError(f"Cloudflare Access logs: {detail}")
                return payload.get("result") or []


def cloudflare_event_id(item):
    """Stable dedupe key; Ray ID is preferred, with a deterministic fallback."""
    return item.get("ray_id") or "|".join(
        str(item.get(key, ""))
        for key in ("created_at", "user_email", "ip_address", "app_domain", "action")
    )
