"""Security event parsing, correlation and Cloudflare Access log retrieval.

The Discord-specific presentation stays in ``main.py``.  Keeping parsing and
correlation here makes the sensitive parts deterministic and unit-testable.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import re
from urllib.parse import urlsplit

import aiohttp


# El sufijo de clave (`ssh2: ED25519 SHA256:...`) lo emite sshd con LogLevel
# INFO, sin necesidad de VERBOSE. Es la unica pista en el log que distingue
# "entro Luca" de "entro el bot de Ansible" cuando ambos usan el mismo usuario
# Unix: el usuario y la IP de origen son identicos, el fingerprint no.
_SSH_KEY_SUFFIX = (
    r"(?:\s+ssh\d*:\s*(?P<key_type>[A-Za-z0-9-]+)\s+"
    r"(?P<fingerprint>(?:SHA256|MD5):\S+))?"
)
_SSH_LOGIN_RE = re.compile(
    r"\bAccepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
    + _SSH_KEY_SUFFIX
)
_SSH_FAIL_RE = re.compile(
    r"\bFailed\s+(?P<method>\S+)\s+for\s+(?P<invalid>invalid user\s+)?"
    r"(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<port>\d+))?"
    + _SSH_KEY_SUFFIX
)
_SSH_PAM_FAIL_RE = re.compile(
    r"\bauthentication failure;.*\brhost=(?P<ip>[0-9a-fA-F:.]+)"
    r"(?:\s+user=(?P<user>\S+))?"
)
# sshd emite "Invalid user X from IP port N" ANTES de cualquier intento de
# credencial, asi que un escaneo de usuarios nunca produce un "Failed ...".
# Sin esta linea, enumerar cuentas es invisible para el bot.
_SSH_INVALID_USER_RE = re.compile(
    r"\bInvalid user\s+(?P<user>\S*)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)"
    r"(?:\s+port\s+(?P<port>\d+))?"
)
# Cliente que negocia y se va sin autenticar: el patron tipico de un scanner.
_SSH_PREAUTH_RE = re.compile(
    r"\b(?:Connection closed|Connection reset|Disconnected)\s+"
    r"(?:by|from)\s+(?:authenticating user\s+(?P<user>\S+)\s+)?"
    r"(?P<invalid>invalid user\s+(?P<invalid_user>\S+)\s+)?"
    r"(?P<ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<port>\d+))?"
    r".*\[preauth\]"
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


def _access_app_parts(value):
    """Return a normalized ``(host[:port], path)`` for an Access app URL."""
    raw = str(value or "").strip().lower()
    if not raw:
        return "", ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        return "", ""
    authority = f"{host}:{port}" if host and port else host
    path = "/" + parsed.path.strip("/") if parsed.path.strip("/") else ""
    return authority.rstrip("."), path


def access_app_matches(configured, observed):
    """Match an Access application exactly by host and, if set, path prefix."""
    configured_host, configured_path = _access_app_parts(configured)
    observed_host, observed_path = _access_app_parts(observed)
    if not configured_host:
        return True
    if configured_host != observed_host:
        return False
    if not configured_path:
        return True
    return (
        observed_path == configured_path
        or observed_path.startswith(f"{configured_path}/")
    )


def classify_ssh_origin(observed_ip, effective_ip, safe_subnets, correlated=False):
    """Describe an SSH origin without treating a local proxy as an Internet IP."""
    if is_loopback(observed_ip) and not correlated:
        return {
            "is_local": False,
            "unresolved_proxy": True,
            "label": "Proxy local · origen público no disponible",
        }
    is_local = any(
        str(effective_ip or "").startswith(prefix)
        for prefix in safe_subnets
        if prefix
    )
    return {
        "is_local": is_local,
        "unresolved_proxy": False,
        "label": "Red local" if is_local else "⚠️ IP externa",
    }


def _normalize_fingerprint(value):
    """``SHA256:abc`` and a bare ``abc`` must hash to the same directory key."""
    text = str(value or "").strip()
    if not text:
        return ""
    return text.split(" ", 1)[0]


def parse_ssh_line(line):
    """Return a normalized SSH event dict, or ``None`` for unrelated lines.

    Every returned event carries ``fingerprint`` and ``method`` (possibly
    empty) so callers never have to branch on which regex matched.
    """
    match = _SSH_LOGIN_RE.search(line)
    if match:
        values = match.groupdict()
        return {
            "kind": "ssh_login",
            "invalid_user": False,
            **values,
            "fingerprint": _normalize_fingerprint(values.get("fingerprint")),
        }
    match = _SSH_FAIL_RE.search(line)
    if match:
        values = match.groupdict()
        invalid = bool(values.pop("invalid", None))
        return {
            "kind": "ssh_fail",
            **values,
            "invalid_user": invalid,
            "fingerprint": _normalize_fingerprint(values.get("fingerprint")),
        }
    match = _SSH_INVALID_USER_RE.search(line)
    if match:
        values = match.groupdict()
        return {
            "kind": "ssh_fail",
            "user": values.get("user") or "desconocido",
            "ip": values["ip"],
            "port": values.get("port"),
            "method": "none",
            "key_type": None,
            "fingerprint": "",
            "invalid_user": True,
            "probe": True,
        }
    match = _SSH_PAM_FAIL_RE.search(line)
    if match:
        values = match.groupdict()
        return {
            "kind": "ssh_fail",
            "user": values.get("user") or "desconocido",
            "ip": values["ip"],
            "port": None,
            "method": "password",
            "key_type": None,
            "fingerprint": "",
            "invalid_user": False,
        }
    match = _SSH_PREAUTH_RE.search(line)
    if match:
        values = match.groupdict()
        user = values.get("user") or values.get("invalid_user") or "desconocido"
        return {
            "kind": "ssh_fail",
            "user": user,
            "ip": values["ip"],
            "port": values.get("port"),
            "method": "none",
            "key_type": None,
            "fingerprint": "",
            "invalid_user": bool(values.get("invalid")),
            "probe": True,
        }
    return None


_SSH_KEYGEN_RE = re.compile(
    r"^\s*(?P<bits>\d+)\s+(?P<fingerprint>(?:SHA256|MD5):\S+)\s+"
    r"(?P<comment>.*?)\s+\((?P<key_type>[A-Za-z0-9-]+)\)\s*$"
)


def parse_ssh_keygen_fingerprints(output):
    """Parse ``ssh-keygen -lf authorized_keys`` into fingerprint records.

    ``ssh-keygen`` prints ``no comment`` when a key has none; that string is
    not an identity and would otherwise become a label.
    """
    entries = []
    for line in str(output or "").splitlines():
        match = _SSH_KEYGEN_RE.match(line)
        if not match:
            continue
        values = match.groupdict()
        comment = values["comment"].strip()
        entries.append({
            "fingerprint": values["fingerprint"],
            "comment": "" if comment == "no comment" else comment,
            "key_type": values["key_type"],
            "bits": int(values["bits"]),
        })
    return entries


class SshKeyDirectory:
    """Maps an SSH fingerprint to a human identity.

    Two sources, in order of precedence: explicit labels (from configuration)
    and the comment field of ``authorized_keys``.  The comment is a good
    default because it is already maintained by whoever installs the key, but
    it is not authoritative -- several keys in this fleet share the comment
    ``luca@archlinux`` while belonging to different automations, which is
    exactly what the explicit labels are for.

    A fingerprint that is absent from every ``authorized_keys`` is the signal
    that matters most: sshd accepted a key nobody can account for.
    """

    def __init__(self, labels=None):
        self._labels = {
            _normalize_fingerprint(key): str(value)
            for key, value in (labels or {}).items()
            if _normalize_fingerprint(key) and value
        }
        self._entries = {}
        self._users = {}
        self.covered_users = set()
        self.updated_at = None

    def load(self, entries, covered_users=(), now=None):
        """Index fingerprints and remember whose keyrings could be read.

        ``covered_users`` is not cosmetic: the agent runs unprivileged and may
        be unable to read ``/root/.ssh/authorized_keys``.  Without that set, a
        legitimate root login would be reported as an unrecognized key on every
        single connection, and an alert that cries wolf nightly gets muted.
        """
        self._entries = {}
        self._users = {}
        for entry in entries or ():
            key = _normalize_fingerprint(entry.get("fingerprint"))
            if not key:
                continue
            self._entries.setdefault(key, entry)
            user = str(entry.get("user") or "")
            if user:
                self._users.setdefault(key, set()).add(user)
        self.covered_users = {str(user) for user in covered_users if user}
        self.updated_at = parse_timestamp(now)
        return self

    def __len__(self):
        return len(self._entries)

    @property
    def loaded(self):
        return self.updated_at is not None

    def covers(self, user):
        """True when this user's keyring was actually read."""
        return str(user or "") in self.covered_users

    def is_authorized(self, fingerprint):
        """False also when the directory is empty: unknown is not authorized.

        Callers must consult :attr:`loaded` to tell "no key is authorized" from
        "the directory was never loaded"; treating an unloaded directory as
        permissive would silence the one alert worth having.
        """
        return _normalize_fingerprint(fingerprint) in self._entries

    def authorized_users(self, fingerprint):
        """Unix accounts whose ``authorized_keys`` list this fingerprint."""
        return set(self._users.get(_normalize_fingerprint(fingerprint), ()))

    def items(self):
        """``(fingerprint, entry)`` pairs, ordered by the owning account."""
        return sorted(
            self._entries.items(),
            key=lambda item: (
                sorted(self.authorized_users(item[0])),
                item[1].get("comment", ""),
            ),
        )

    def describe(self, fingerprint):
        """Return ``(label, known)`` for a fingerprint."""
        key = _normalize_fingerprint(fingerprint)
        if not key:
            return "", False
        if key in self._labels:
            return self._labels[key], True
        entry = self._entries.get(key)
        if entry is None:
            return "", False
        return entry.get("comment") or "clave sin comentario", True

    def short(self, fingerprint):
        """Fingerprint trimmed for an embed; the full value stays in the log."""
        key = _normalize_fingerprint(fingerprint)
        if not key:
            return ""
        body = key.split(":", 1)[1] if ":" in key else key
        return body[:12]


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

    def nearest_cloudflare_access(
        self,
        at=None,
        max_skew_seconds=180,
        app_domain="",
        excluded_ids=None,
    ):
        """Return the closest unused, allowed Access event for one application.

        A symmetric window tolerates small clock differences between Cloudflare
        and the SSH host.  Callers claim the returned event ID so one browser
        authentication cannot be attributed to multiple SSH sessions.
        """
        at = parse_timestamp(at)
        excluded_ids = set(excluded_ids or ())
        maximum_skew = timedelta(seconds=max_skew_seconds)
        candidates = []
        for event in self.events:
            if event.kind != "cloudflare_access":
                continue
            if not event.metadata.get("allowed") or not event.ip:
                continue
            action = str(event.metadata.get("action") or "").lower()
            if action and "login" not in action:
                continue
            event_id = str(event.metadata.get("event_id") or "")
            if event_id and event_id in excluded_ids:
                continue
            if not access_app_matches(
                app_domain, event.metadata.get("app_domain", "")
            ):
                continue
            skew = abs(event.timestamp - at)
            if skew <= maximum_skew:
                candidates.append((skew, -event.timestamp.timestamp(), event))
        return min(candidates, key=lambda value: value[:2], default=(None, None, None))[2]


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
