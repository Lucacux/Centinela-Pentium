#!/usr/bin/env bash
set -euo pipefail

DEST=${GEOIP_COUNTRY_DB:-/var/lib/GeoIP/Country.mmdb}
PYTHON=${CENTINELA_PYTHON:-/mnt/virtual_storage/Bot_Discord/venv/bin/python}
BASE_URL=https://download.db-ip.com/free

task_tmp=$(mktemp -d /tmp/centinela-geoip.XXXXXX)
trap 'rm -rf -- "$task_tmp"' EXIT

archive="$task_tmp/country.mmdb.gz"
candidate="$task_tmp/country.mmdb"
month_start=$(date -u +%Y-%m-01)
release=""

# Early in a month the new file may not exist yet; keep the previous release as
# a safe fallback instead of deleting a valid database.
for months_ago in 0 1; do
    release=$(date -u -d "$month_start -$months_ago month" +%Y-%m)
    if curl --fail --location --silent --show-error \
        "$BASE_URL/dbip-country-lite-$release.mmdb.gz" \
        --output "$archive"; then
        break
    fi
    release=""
done

if [[ -z "$release" ]]; then
    echo "No DB-IP Country Lite release was available" >&2
    exit 1
fi

gzip --test "$archive"
gzip -dc "$archive" > "$candidate"

"$PYTHON" - "$candidate" <<'PY'
import sys
from geoip2.database import Reader

with Reader(sys.argv[1]) as reader:
    database_type = reader.metadata().database_type
    if not database_type.startswith("DBIP-"):
        raise SystemExit(f"Unexpected MMDB type: {database_type}")
    if not reader.country("1.1.1.1").country.iso_code:
        raise SystemExit("MMDB validation lookup returned no country")
PY

dest_dir=$(dirname "$DEST")
if [[ ! -d "$dest_dir" ]]; then
    install -d -m 0755 "$dest_dir"
fi
if [[ -f "$DEST" ]] && cmp --silent "$candidate" "$DEST"; then
    echo "DB-IP Country Lite $release is already current"
    exit 0
fi
install -m 0644 "$candidate" "$DEST"
echo "Installed DB-IP Country Lite $release at $DEST"
