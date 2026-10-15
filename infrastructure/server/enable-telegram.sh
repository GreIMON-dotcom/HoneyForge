#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
touch .server.env
grep -v -E '^(TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID)=' .server.env > .server.env.tmp || true
if [ "${1-}" != "off" ]; then
  printf 'Токен бота: '
  stty -echo 2>/dev/null || true
  read -r token
  stty echo 2>/dev/null || true
  printf '\nИдентификатор чата: '
  read -r chat
  case "$token" in
    [0-9]*:[A-Za-z0-9_-]*) ;;
    *) rm -f .server.env.tmp; echo "Токен не похож на токен бота Telegram" >&2; exit 2 ;;
  esac
  case "$chat" in
    ''|*[!0-9-]*) rm -f .server.env.tmp; echo "Идентификатор чата должен быть числом" >&2; exit 2 ;;
  esac
  printf 'TELEGRAM_BOT_TOKEN=%s\nTELEGRAM_CHAT_ID=%s\n' "$token" "$chat" >> .server.env.tmp
  echo "Уведомления включены для чата $chat"
else
  echo "Уведомления выключены"
fi
mv .server.env.tmp .server.env
chmod 600 .server.env
