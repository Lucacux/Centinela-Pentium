#!/usr/bin/env python3
"""Restricted collector used by the central Centinela over a forced SSH key.

The SSH authorized_keys entry forces every connection through this program.
Only the operations dispatched below are available; arbitrary shell commands
are never evaluated.
"""

from datetime import datetime
import glob
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

import psutil


AGENT_VERSION = 1
CONFIG_PATH = os.getenv(
    "CENTINELA_AGENT_CONFIG", "/etc/centinela-agent.json"
)
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_OUTPUT = 200_000


def load_config():
    defaults = {
        "name": "arch",
        "watched_services": [],
        "allowed_restart": [],
        "backup_path": "",
        "ignored_ssh_key_fingerprints": [],
        "smart_devices": [
            "/dev/sda",
            "/dev/nvme0n1",
            "/dev/nvme0",
            "/dev/vda",
        ],
    }
    try:
        with open(CONFIG_PATH, encoding="utf-8") as handle:
            configured = json.load(handle)
        if isinstance(configured, dict):
            defaults.update(configured)
    except (FileNotFoundError, OSError, ValueError):
        pass
    return defaults


CONFIG = load_config()


def run(args, timeout=20):
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output[-MAX_OUTPUT:]
    except (OSError, subprocess.SubprocessError) as error:
        return 127, str(error)


def distro():
    values = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as handle:
            for line in handle:
                if "=" not in line:
                    continue
                key, value = line.rstrip().split("=", 1)
                values[key] = value.strip('"')
    except OSError:
        pass
    return values.get("ID", "unknown")


def temperatures():
    result = {}
    try:
        for chip, entries in psutil.sensors_temperatures().items():
            for index, entry in enumerate(entries):
                label = entry.label or f"{chip}_{index}"
                key = label if label not in result else f"{chip}:{label}"
                if entry.current is not None:
                    current = float(entry.current)
                    # ACPI commonly exposes disconnected channels as -127°C
                    # or 0°C. Reporting those as real temperatures is worse
                    # than marking the sensor unavailable.
                    if 0 < current < 150:
                        result[key] = round(current, 1)
    except (AttributeError, OSError):
        pass
    return result


def service_states():
    states = {}
    for service in CONFIG.get("watched_services", []):
        if not NAME_RE.fullmatch(str(service)):
            continue
        code, output = run(
            ["systemctl", "is-active", str(service)], timeout=8
        )
        states[str(service)] = (
            output.strip().splitlines()[0]
            if output.strip() else ("active" if code == 0 else "unknown")
        )
    return states


def network_up():
    code, _ = run(["ping", "-c", "1", "-W", "3", "1.1.1.1"], timeout=5)
    return code == 0


def snapshot():
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    swap = psutil.swap_memory()
    net = psutil.net_io_counters()
    return {
        "agent_version": AGENT_VERSION,
        "name": CONFIG.get("name", "arch"),
        "hostname": Path("/proc/sys/kernel/hostname").read_text().strip(),
        "distro": distro(),
        "cpu_percent": psutil.cpu_percent(interval=0.25),
        "ram_percent": ram.percent,
        "ram_used": ram.used,
        "ram_total": ram.total,
        "disk_percent": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "swap_percent": swap.percent,
        "swap_used": swap.used,
        "swap_total": swap.total,
        "load1": os.getloadavg()[0],
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
        "net_sent": net.bytes_sent,
        "net_recv": net.bytes_recv,
        "network_up": network_up(),
        "temperatures": temperatures(),
        "services": service_states(),
        "timestamp": datetime.now().astimezone().isoformat(),
    }


def top_processes(limit=8):
    limit = max(1, min(int(limit), 20))
    processes = {}
    for proc in psutil.process_iter(["pid"]):
        try:
            proc.cpu_percent(interval=None)
            processes[proc.pid] = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    time.sleep(0.35)
    rows = []
    cpu_count = psutil.cpu_count() or 1
    for proc in processes.values():
        try:
            with proc.oneshot():
                rows.append({
                    "pid": proc.pid,
                    "name": proc.name(),
                    "cpu": round(proc.cpu_percent(interval=None) / cpu_count, 1),
                    "ram": round(proc.memory_percent() or 0.0, 1),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue
    return {
        "cpu": sorted(rows, key=lambda item: item["cpu"], reverse=True)[:limit],
        "ram": sorted(rows, key=lambda item: item["ram"], reverse=True)[:limit],
    }


def open_ports():
    rows = []
    seen = set()
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        connections = []
    for conn in connections:
        if conn.status != psutil.CONN_LISTEN:
            continue
        key = (conn.laddr.ip, conn.laddr.port)
        if key in seen:
            continue
        seen.add(key)
        process = "?"
        if conn.pid:
            try:
                process = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        rows.append({
            "ip": conn.laddr.ip,
            "port": conn.laddr.port,
            "pid": conn.pid or 0,
            "process": process,
        })
    return sorted(rows, key=lambda item: (item["port"], item["ip"]))[:100]


def sessions():
    rows = []
    for user in psutil.users():
        rows.append({
            "user": user.name,
            "terminal": user.terminal or "?",
            "host": user.host or "local",
            "started": datetime.fromtimestamp(
                user.started
            ).astimezone().isoformat(),
        })
    return rows[:50]


def smart_health(allow_sudo=True):
    if not shutil.which("smartctl"):
        return {"available": False}
    if allow_sudo and os.geteuid() != 0 and shutil.which("sudo"):
        code, output = run([
            "sudo", "-n", sys.executable, str(Path(__file__).resolve()),
            "--smart-helper",
        ], timeout=35)
        if code == 0:
            try:
                payload = json.loads(output)
            except ValueError:
                payload = None
            if isinstance(payload, dict) and payload.get("ok"):
                payload.pop("ok", None)
                return payload
    for device in CONFIG.get("smart_devices", []):
        if not os.path.exists(device):
            continue
        code, output = run(["smartctl", "-H", "-A", device], timeout=30)
        return {
            "available": True,
            "device": device,
            "healthy": "PASSED" in output or "OK" in output,
            "returncode": code,
            "output": output[-12_000:],
        }
    return {"available": True, "device": "", "output": ""}


def docker_containers():
    if not shutil.which("docker"):
        return {"available": False, "containers": []}
    _, raw = run(
        ["docker", "ps", "-a", "--format", "{{json .}}"], timeout=20
    )
    containers = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        containers.append({
            "name": value.get("Names", ""),
            "status": value.get("Status", ""),
            "state": value.get("State", ""),
            "image": value.get("Image", ""),
            "ports": value.get("Ports", ""),
        })

    _, raw_stats = run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
        timeout=30,
    )
    stats = {}
    for line in raw_stats.splitlines():
        try:
            value = json.loads(line)
            name = value.get("Name", "")
            stats[name] = {
                "cpu": float(value.get("CPUPerc", "0").rstrip("%") or 0),
                "ram": float(value.get("MemPerc", "0").rstrip("%") or 0),
                "mem_usage": value.get("MemUsage", ""),
            }
        except (ValueError, TypeError):
            continue
    for container in containers:
        container.update(stats.get(container["name"], {
            "cpu": 0.0, "ram": 0.0, "mem_usage": "",
        }))
    return {"available": True, "containers": containers}


def validate_name(value):
    if not NAME_RE.fullmatch(value or ""):
        raise ValueError("invalid resource name")
    return value


def docker_logs(name, lines=25):
    name = validate_name(name)
    lines = max(1, min(int(lines), 100))
    code, output = run(
        ["docker", "logs", "--tail", str(lines), name], timeout=25
    )
    return {"ok": code == 0, "name": name, "output": output[-12_000:]}


def docker_restart(name):
    name = validate_name(name)
    allowed = set(CONFIG.get("allowed_restart", []))
    if name not in allowed:
        raise PermissionError(f"{name} is not in allowed_restart")
    code, output = run(["docker", "restart", name], timeout=60)
    return {"ok": code == 0, "name": name, "output": output[-2_000:]}


def docker_heal(name):
    name = validate_name(name)
    code, state = run(
        ["docker", "inspect", "--format", "{{.State.Status}}", name],
        timeout=10,
    )
    if code != 0 or state.strip() != "restarting":
        raise PermissionError(f"{name} is not restarting")
    code, output = run(["docker", "restart", name], timeout=60)
    return {"ok": code == 0, "name": name, "output": output[-2_000:]}


def package_updates():
    if distro() != "arch":
        return {"manager": "unknown", "updates": []}
    if shutil.which("checkupdates"):
        code, output = run(["checkupdates"], timeout=90)
        if code not in (0, 2):
            output = ""
    else:
        _, output = run(["pacman", "-Qu"], timeout=30)
    updates = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "->":
            updates.append({
                "package": parts[0],
                "old": parts[1],
                "new": parts[3],
            })
    return {"manager": "pacman", "updates": updates[:500]}


def backup_status():
    path = str(CONFIG.get("backup_path") or "")
    if not path:
        return {"configured": False}
    candidates = glob.glob(os.path.join(path, "index.*"))
    if not candidates:
        return {"configured": True, "exists": os.path.isdir(path)}
    newest = max(candidates, key=os.path.getmtime)
    size = 0
    for root, _, files in os.walk(path):
        for filename in files:
            try:
                size += os.path.getsize(os.path.join(root, filename))
            except OSError:
                pass
    return {
        "configured": True,
        "exists": True,
        "index": os.path.basename(newest),
        "last_timestamp": os.path.getmtime(newest),
        "size": size,
    }


def security_events(since_epoch):
    now = int(time.time())
    since_epoch = max(now - 86_400, min(int(since_epoch), now))
    code, output = run([
        "journalctl",
        "-u", "sshd",
        "-u", "fail2ban",
        "--since", f"@{since_epoch}",
        "--no-pager",
        "-o", "json",
    ], timeout=25)
    if code != 0:
        return {"events": [], "error": output[-1_000:]}
    events = []
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        message = str(value.get("MESSAGE", ""))
        if any(
            fingerprint and fingerprint in message
            for fingerprint in CONFIG.get(
                "ignored_ssh_key_fingerprints", []
            )
        ):
            continue
        if not any(marker in message for marker in (
            "Accepted ",
            "Failed password",
            "authentication failure",
            "] Ban ",
            "] Unban ",
        )):
            continue
        timestamp = int(value.get("__REALTIME_TIMESTAMP", 0) or 0) / 1_000_000
        events.append({
            "timestamp": timestamp,
            "unit": value.get("_SYSTEMD_UNIT", ""),
            "message": message[-4_000:],
        })
    return {"events": events[-500:]}


def dispatch(argv):
    if not argv:
        argv = ["hello"]
    action = argv[0]
    if action == "hello":
        return {
            "ok": True,
            "agent_version": AGENT_VERSION,
            "name": CONFIG.get("name", "arch"),
        }
    if action == "snapshot":
        return snapshot()
    if action == "top":
        return top_processes(argv[1] if len(argv) > 1 else 8)
    if action == "ports":
        return {"ports": open_ports()}
    if action == "sessions":
        return {"sessions": sessions()}
    if action == "smart":
        return smart_health()
    if action == "docker":
        return docker_containers()
    if action == "logs" and len(argv) >= 2:
        return docker_logs(argv[1], argv[2] if len(argv) > 2 else 25)
    if action == "restart" and len(argv) == 2:
        return docker_restart(argv[1])
    if action == "heal" and len(argv) == 2:
        return docker_heal(argv[1])
    if action == "updates":
        return package_updates()
    if action == "backup":
        return backup_status()
    if action == "security" and len(argv) == 2:
        return security_events(argv[1])
    raise ValueError("unsupported operation")


def smart_helper_main():
    if os.geteuid() != 0:
        payload = {"ok": False, "error": "smart helper requires root"}
    else:
        payload = smart_health(allow_sudo=False)
        payload.setdefault("ok", True)
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0 if payload.get("ok") else 1


def main():
    original = os.getenv("SSH_ORIGINAL_COMMAND", "")
    try:
        argv = shlex.split(original)
        payload = dispatch(argv)
        if not isinstance(payload, dict):
            payload = {"result": payload}
        payload.setdefault("ok", True)
    except (ValueError, PermissionError) as error:
        payload = {"ok": False, "error": str(error)}
    except Exception as error:
        payload = {"ok": False, "error": f"agent failure: {error}"}
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--smart-helper"]:
        sys.exit(smart_helper_main())
    sys.exit(main())
