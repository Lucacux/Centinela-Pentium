#!/usr/bin/env python3
"""Atomically update the non-secret REMOTE_ARCH settings in an existing .env."""

import os
from pathlib import Path
import stat
import sys
import tempfile


ALLOWED = {
    "REMOTE_ARCH_ENABLED",
    "REMOTE_ARCH_KEY",
    "REMOTE_ARCH_NAME",
    "REMOTE_ARCH_HOST",
    "REMOTE_ARCH_USER",
    "REMOTE_ARCH_IDENTITY_FILE",
    "REMOTE_ARCH_KNOWN_HOSTS",
    "REMOTE_ARCH_TIMEOUT",
    "REMOTE_ARCH_TEMP_ALERT_C",
    "REMOTE_ARCH_SWAP_ALERT_PCT",
    "REMOTE_ARCH_SSH_FAIL_THRESHOLD",
    "REMOTE_ARCH_SSH_FAIL_WINDOW",
}


def main():
    if len(sys.argv) < 3:
        raise SystemExit(f"usage: {sys.argv[0]} <env-file> KEY=VALUE [...]")
    target = Path(sys.argv[1]).resolve()
    updates = {}
    for item in sys.argv[2:]:
        key, separator, value = item.partition("=")
        if not separator or key not in ALLOWED or "\n" in value or "\r" in value:
            raise SystemExit(f"invalid setting: {item!r}")
        updates[key] = value
    if not target.is_file():
        raise SystemExit(f"env file does not exist: {target}")

    original = target.read_text(encoding="utf-8").splitlines()
    output = []
    replaced = set()
    for line in original:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in updates:
            if key not in replaced:
                output.append(f"{key}={updates[key]}")
                replaced.add(key)
        else:
            output.append(line)
    missing = [key for key in updates if key not in replaced]
    if missing:
        if output and output[-1]:
            output.append("")
        output.append("# --- Nodo Arch remoto (agente SSH restringido) ---")
        output.extend(f"{key}={updates[key]}" for key in missing)

    file_stat = target.stat()
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(output) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(file_stat.st_mode))
        os.chown(temporary, file_stat.st_uid, file_stat.st_gid)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main()
