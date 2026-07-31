#!/usr/bin/env python3
"""Export network endpoints for containers and non-containerized services.

The output is Prometheus textfile-collector data. Discovery is deliberately
local and read-only: Docker inspect, systemd unit state, ``ss`` and /proc
cgroups. No service is restarted or reconfigured.
"""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile


PID_RE = re.compile(r"\bpid=(\d+)")
SERVICE_RE = re.compile(r"(?:^|/)([^/]+\.service)(?:$|/)")


def run(args, timeout=30):
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def host_ipv4():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 53))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def split_endpoint(value):
    """Split ss/Docker address notation into address and numeric port."""
    value = str(value or "").strip()
    if value.startswith("[") and "]:" in value:
        address, port = value[1:].rsplit("]:", 1)
    elif ":" in value:
        address, port = value.rsplit(":", 1)
    else:
        return "", ""
    if not port.isdigit():
        return "", ""
    return address, port


def display_ip(bind, fallback):
    if bind in ("0.0.0.0", "::", "*", ""):
        return fallback
    return bind


def scope_of(bind):
    if bind in ("127.0.0.1", "::1"):
        return "local"
    if bind in ("0.0.0.0", "::", "*", ""):
        return "lan"
    return "interface"


def container_endpoints(host, address):
    if run(["docker", "info"], timeout=10)[0] != 0:
        return []
    code, names_raw = run(
        ["docker", "ps", "--format", "{{.Names}}"], timeout=15
    )
    names = [line.strip() for line in names_raw.splitlines() if line.strip()]
    if code != 0 or not names:
        return []
    code, raw = run(["docker", "inspect", *names], timeout=30)
    if code != 0:
        return []
    try:
        inspected = json.loads(raw)
    except ValueError:
        return []

    rows = []
    for item in inspected:
        config = item.get("Config") or {}
        labels = config.get("Labels") or {}
        name = (
            labels.get("com.docker.swarm.service.name")
            or str(item.get("Name") or "").lstrip("/")
        )
        state = str((item.get("State") or {}).get("Status") or "unknown")
        network = item.get("NetworkSettings") or {}
        ports = network.get("Ports") or {}
        emitted = set()
        for private, bindings in ports.items():
            private_port, _, protocol = private.partition("/")
            if bindings:
                for binding in bindings:
                    bind = str(binding.get("HostIp") or "0.0.0.0")
                    port = str(binding.get("HostPort") or "")
                    if not port.isdigit():
                        continue
                    ip = display_ip(bind, address)
                    key = (ip, port, protocol or "tcp")
                    if key in emitted:
                        continue
                    emitted.add(key)
                    rows.append({
                        "host": host,
                        "runtime": "container",
                        "service": name,
                        "state": state,
                        "bind": bind,
                        "ip": ip,
                        "port": port,
                        "protocol": protocol or "tcp",
                        "scope": scope_of(bind),
                    })
                continue
            # Exposed but not published: report the container-network endpoint
            # instead of pretending it is reachable on the host address.
            container_ip = next(
                (
                    values.get("IPAddress")
                    for values in (network.get("Networks") or {}).values()
                    if values.get("IPAddress")
                ),
                "",
            )
            if container_ip and private_port.isdigit():
                rows.append({
                    "host": host,
                    "runtime": "container-internal",
                    "service": name,
                    "state": state,
                    "bind": container_ip,
                    "ip": container_ip,
                    "port": private_port,
                    "protocol": protocol or "tcp",
                    "scope": "container-network",
                })
    return rows


def service_for_pid(pid):
    try:
        content = Path(f"/proc/{int(pid)}/cgroup").read_text(encoding="utf-8")
    except (OSError, ValueError):
        return ""
    match = SERVICE_RE.search(content)
    return match.group(1) if match else ""


def systemd_endpoints(host, address):
    code, raw = run(["ss", "-H", "-lntup"], timeout=15)
    if code != 0:
        return []
    rows = []
    seen = set()
    ignored = {"docker.service", "containerd.service"}
    for line in raw.splitlines():
        columns = line.split()
        if len(columns) < 6:
            continue
        protocol = columns[0].lower()
        bind, port = split_endpoint(columns[4])
        if not port:
            continue
        pids = PID_RE.findall(line)
        services = {
            service_for_pid(pid) for pid in pids
        } - {"", *ignored}
        for unit in services:
            key = (unit, bind, port, protocol)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "host": host,
                "runtime": "systemd",
                "service": unit.removesuffix(".service"),
                "state": "running",
                "bind": bind,
                "ip": display_ip(bind, address),
                "port": port,
                "protocol": protocol,
                "scope": scope_of(bind),
            })
    return rows


def prom_escape(value):
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def render(rows):
    lines = [
        "# HELP centinela_runtime_endpoint_info Discovered listening endpoint.",
        "# TYPE centinela_runtime_endpoint_info gauge",
    ]
    for row in sorted(
        rows,
        key=lambda item: (
            item["host"], item["runtime"], item["service"],
            item["ip"], int(item["port"]), item["protocol"],
        ),
    ):
        endpoint = f"{row['ip']}:{row['port']}/{row['protocol']}"
        labels = {**row, "endpoint": endpoint}
        encoded = ",".join(
            f'{key}="{prom_escape(value)}"'
            for key, value in sorted(labels.items())
        )
        lines.append(f"centinela_runtime_endpoint_info{{{encoded}}} 1")
    return "\n".join(lines) + "\n"


def atomic_write(path, content):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="/var/lib/node-exporter-textfile/centinela-runtime.prom",
    )
    parser.add_argument("--host", default=socket.gethostname().split(".")[0])
    options = parser.parse_args()
    address = host_ipv4()
    rows = (
        container_endpoints(options.host, address)
        + systemd_endpoints(options.host, address)
    )
    atomic_write(options.output, render(rows))


if __name__ == "__main__":
    main()
