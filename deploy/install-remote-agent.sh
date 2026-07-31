#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 || "$#" -ne 4 ]]; then
  echo "usage: sudo $0 <agent.py> <config.json> <public-key-file> <target-user>" >&2
  exit 2
fi

agent_source=$1
config_source=$2
public_key_file=$3
target_user=$4

for source_file in "$agent_source" "$config_source" "$public_key_file"; do
  if [[ ! -f "$source_file" ]]; then
    echo "missing file: $source_file" >&2
    exit 2
  fi
done

target_home=$(getent passwd "$target_user" | cut -d: -f6)
if [[
  ! "$target_user" =~ ^[a-z_][a-z0-9_-]*[$]?$ ||
  -z "$target_home" ||
  ! -d "$target_home"
 ]]; then
  echo "invalid target user: $target_user" >&2
  exit 2
fi

public_key=$(tr -d '\r\n' < "$public_key_file")
if [[ ! "$public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; then
  echo "only one valid Ed25519 public key is accepted" >&2
  exit 2
fi

fingerprint=$(ssh-keygen -lf "$public_key_file" | awk 'NR == 1 {print $2}')
if [[ ! "$fingerprint" =~ ^SHA256:[A-Za-z0-9+/]+$ ]]; then
  echo "could not derive Ed25519 key fingerprint" >&2
  exit 2
fi

config_with_fingerprint=$(mktemp /tmp/centinela-agent-config.XXXXXX)
sudoers_candidate=$(mktemp /tmp/centinela-agent-sudoers.XXXXXX)
trap 'rm -f -- "$config_with_fingerprint" "$sudoers_candidate"' EXIT
python3 -c '
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)
config["ignored_ssh_key_fingerprints"] = [sys.argv[2]]
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
' "$config_source" "$fingerprint" "$config_with_fingerprint"

install -d -o root -g root -m 0755 /opt/centinela-agent
install -o root -g root -m 0755 "$agent_source" /opt/centinela-agent/remote_agent.py
install -o root -g root -m 0644 "$config_with_fingerprint" /etc/centinela-agent.json

if [[ ! -x /opt/centinela-agent/venv/bin/python ]]; then
  python3 -m venv /opt/centinela-agent/venv
fi
/opt/centinela-agent/venv/bin/python -m pip install \
  --disable-pip-version-check --quiet "psutil==7.2.2"

printf '%s ALL=(root) NOPASSWD: %s\n' \
  "$target_user" \
  "/opt/centinela-agent/venv/bin/python /opt/centinela-agent/remote_agent.py --smart-helper" \
  > "$sudoers_candidate"
chmod 0440 "$sudoers_candidate"
visudo -cf "$sudoers_candidate" >/dev/null
install -o root -g root -m 0440 \
  "$sudoers_candidate" /etc/sudoers.d/centinela-agent-smart

ssh_dir="$target_home/.ssh"
authorized_keys="$ssh_dir/authorized_keys"
install -d -o "$target_user" -g "$target_user" -m 0700 "$ssh_dir"
touch "$authorized_keys"
chown "$target_user:$target_user" "$authorized_keys"
chmod 0600 "$authorized_keys"

forced_entry="restrict,command=\"/opt/centinela-agent/venv/bin/python /opt/centinela-agent/remote_agent.py\" $public_key"
if ! grep -Fqx "$forced_entry" "$authorized_keys"; then
  cp -a "$authorized_keys" "${authorized_keys}.bak.$(date +%Y%m%d%H%M%S)"
  printf '%s\n' "$forced_entry" >> "$authorized_keys"
fi

echo "Centinela remote agent installed for $target_user"
