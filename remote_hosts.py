"""Constrained SSH client for hosts managed by the central Centinela."""

import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import subprocess


class RemoteHostError(RuntimeError):
    pass


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True)
class RemoteHostConfig:
    key: str
    name: str
    hostname: str
    user: str
    identity_file: str
    known_hosts_file: str
    timeout: int = 20

    @classmethod
    def from_env(cls, prefix="REMOTE_ARCH"):
        enabled = os.getenv(
            f"{prefix}_ENABLED", "false"
        ).lower() in ("true", "1", "yes")
        hostname = os.getenv(f"{prefix}_HOST", "").strip()
        identity = os.getenv(f"{prefix}_IDENTITY_FILE", "").strip()
        if not enabled or not hostname or not identity:
            return None
        key = os.getenv(f"{prefix}_KEY", "arch").strip().lower()
        name = os.getenv(f"{prefix}_NAME", "server-mbp").strip()
        user = os.getenv(f"{prefix}_USER", "luca").strip()
        known_hosts = os.getenv(
            f"{prefix}_KNOWN_HOSTS",
            "/home/luca/.ssh/known_hosts",
        ).strip()
        try:
            timeout = max(5, int(os.getenv(f"{prefix}_TIMEOUT", "20")))
        except ValueError as error:
            raise RemoteHostError(f"{prefix}_TIMEOUT must be an integer") from error
        if (
            not _HOST_RE.fullmatch(hostname)
            or not _NAME_RE.fullmatch(key)
            or not _NAME_RE.fullmatch(name)
            or not _NAME_RE.fullmatch(user)
        ):
            raise RemoteHostError(f"invalid {prefix} host identity")
        if not Path(identity).is_absolute() or not Path(known_hosts).is_absolute():
            raise RemoteHostError(
                f"{prefix} identity and known_hosts paths must be absolute"
            )
        return cls(
            key=key,
            name=name,
            hostname=hostname,
            user=user,
            identity_file=identity,
            known_hosts_file=known_hosts,
            timeout=timeout,
        )


class RemoteHostClient:
    def __init__(self, config, runner=subprocess.run):
        self.config = config
        self._runner = runner

    def _ssh_argv(self, operation):
        return [
            "ssh",
            "-i", self.config.identity_file,
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.config.known_hosts_file}",
            "-o", f"ConnectTimeout={self.config.timeout}",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=2",
            f"{self.config.user}@{self.config.hostname}",
            operation,
        ]

    def request_sync(self, action, *args, timeout=None):
        values = [str(action), *(str(arg) for arg in args)]
        if any(
            not value
            or "\n" in value
            or "\r" in value
            or len(value) > 256
            for value in values
        ):
            raise RemoteHostError("invalid remote operation")
        operation = shlex.join(values)
        try:
            result = self._runner(
                self._ssh_argv(operation),
                capture_output=True,
                text=True,
                timeout=timeout or self.config.timeout + 10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RemoteHostError(str(error)) from error
        if result.returncode != 0 and not result.stdout.strip():
            detail = result.stderr.strip().splitlines()
            raise RemoteHostError(
                detail[-1] if detail else f"ssh exit {result.returncode}"
            )
        try:
            payload = json.loads(result.stdout)
        except (ValueError, TypeError) as error:
            raise RemoteHostError("remote agent returned invalid JSON") from error
        if not isinstance(payload, dict):
            raise RemoteHostError("remote agent returned a non-object response")
        if not payload.get("ok", False):
            raise RemoteHostError(str(payload.get("error") or "remote operation failed"))
        return payload

    async def request(self, action, *args, timeout=None):
        return await asyncio.to_thread(
            self.request_sync, action, *args, timeout=timeout
        )
