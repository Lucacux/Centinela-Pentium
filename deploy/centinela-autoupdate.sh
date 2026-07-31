#!/usr/bin/env bash
set -euo pipefail

DIR=${CENTINELA_DIR:-/mnt/virtual_storage/Bot_Discord}
BOT=${CENTINELA_SERVICE:-discord-bot.service}
VENV=${CENTINELA_VENV:-"$DIR/venv"}

cd "$DIR"
git fetch --quiet origin main
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [[ "$LOCAL" == "$REMOTE" ]]; then
    echo "No changes (${LOCAL:0:7})"
    exit 0
fi

echo "Update: ${LOCAL:0:7} -> ${REMOTE:0:7}; dependencies + pull + restart $BOT"

# Install the target revision's dependencies before replacing the working tree.
# If dependency resolution fails, the currently running process is left intact.
requirements_tmp=$(mktemp /tmp/centinela-requirements.XXXXXX)
trap 'rm -f -- "$requirements_tmp"' EXIT
git show origin/main:requirements.txt > "$requirements_tmp"
"$VENV/bin/python" -m pip install \
    --disable-pip-version-check \
    --require-virtualenv \
    -r "$requirements_tmp"

git pull --ff-only --quiet origin main
sudo systemctl restart "$BOT"
echo "Restarted $BOT"
