#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
ports="${1-}"
case "$ports" in
  *[!0-9,-]*) echo "Список портов может содержать только цифры, запятые и дефисы" >&2; exit 2 ;;
esac
touch .server.env
grep -v -E '^(PUBLISH_PORTS|PUBLISH_ADDRESS)=' .server.env > .server.env.tmp || true
if [ -n "$ports" ]; then
  printf 'PUBLISH_PORTS=%s\nPUBLISH_ADDRESS=0.0.0.0\n' "$ports" >> .server.env.tmp
fi
mv .server.env.tmp .server.env
chmod 600 .server.env
if [ -n "$ports" ]; then
  echo "Публикация разрешена для портов: $ports"
else
  echo "Публикация выключена"
fi
