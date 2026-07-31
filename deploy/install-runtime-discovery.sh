#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 || "$#" -ne 3 ]]; then
  echo "usage: sudo $0 <discovery.py> <service-unit> <timer-unit>" >&2
  exit 2
fi

discovery_source=$1
service_source=$2
timer_source=$3
textfile_dir=/var/lib/node-exporter-textfile

for source_file in "$discovery_source" "$service_source" "$timer_source"; do
  if [[ ! -f "$source_file" ]]; then
    echo "missing file: $source_file" >&2
    exit 2
  fi
done

if [[ ! -d "$textfile_dir" ]]; then
  echo "node_exporter textfile directory not found: $textfile_dir" >&2
  exit 2
fi

install -d -o root -g root -m 0755 /opt/monitoring/exporter
install -o root -g root -m 0755 \
  "$discovery_source" \
  /opt/monitoring/exporter/centinela-runtime-discovery.py
install -o root -g root -m 0644 \
  "$service_source" \
  /etc/systemd/system/centinela-runtime-discovery.service
install -o root -g root -m 0644 \
  "$timer_source" \
  /etc/systemd/system/centinela-runtime-discovery.timer

systemctl daemon-reload
systemctl enable --now centinela-runtime-discovery.timer
systemctl start centinela-runtime-discovery.service
echo "Centinela runtime inventory installed"
