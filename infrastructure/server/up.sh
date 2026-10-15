#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
python3 infrastructure/scripts/setup.py >/dev/null
profile=""
if grep -q -E '^TELEGRAM_BOT_TOKEN=.+' .server.env 2>/dev/null; then
  profile="--profile notify"
fi
# shellcheck disable=SC2086
exec docker compose --env-file .env --env-file .server.env -f compose.yaml -f compose.server.yaml $profile up --build -d --wait "$@"
