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
if [[ -z "$target_home" || ! -d "$target_home" ]]; then
  echo "invalid target user: $target_user" >&2
  exit 2
fi

public_key=$(tr -d '\r\n' < "$public_key_file")
if [[ ! "$public_key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; then
  echo "only one valid Ed25519 public key is accepted" >&2
  exit 2
fi

python3 -m json.tool "$config_source" >/dev/null
install -d -o root -g root -m 0755 /opt/centinela-agent
install -o root -g root -m 0755 "$agent_source" /opt/centinela-agent/remote_agent.py
install -o root -g root -m 0644 "$config_source" /etc/centinela-agent.json

if [[ ! -x /opt/centinela-agent/venv/bin/python ]]; then
  python3 -m venv /opt/centinela-agent/venv
fi
/opt/centinela-agent/venv/bin/python -m pip install \
  --disable-pip-version-check --quiet "psutil==7.2.2"

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
