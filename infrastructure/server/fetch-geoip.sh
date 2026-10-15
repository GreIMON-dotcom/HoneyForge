#!/bin/sh
# IP to Country Lite: DB-IP, CC BY 4.0.
set -eu
cd "$(dirname "$0")/../.."
month="${1:-$(date -u +%Y-%m)}"
case "$month" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]) ;;
  *) echo "Месяц указывается в виде ГГГГ-ММ" >&2; exit 2 ;;
esac
url="https://download.db-ip.com/free/dbip-country-lite-$month.csv.gz"
target="infrastructure/geoip"
mkdir -p "$target"
echo "Загрузка: $url"
curl --fail --silent --show-error --location --max-time 120 --max-filesize 52428800 -o "$target/ranges.csv.gz.tmp" "$url"
gzip -dc "$target/ranges.csv.gz.tmp" > "$target/ranges.csv.tmp"
rm -f "$target/ranges.csv.gz.tmp"
rows=$(wc -l < "$target/ranges.csv.tmp")
if [ "$rows" -lt 1000 ]; then
  rm -f "$target/ranges.csv.tmp"
  echo "Загруженный файл не похож на базу диапазонов" >&2
  exit 1
fi
mv "$target/ranges.csv.tmp" "$target/ranges.csv"
chmod 644 "$target/ranges.csv"
touch .server.env
grep -v -E '^(GEOIP_PROVIDER|GEOIP_FILE|GEOIP_ATTRIBUTION|GEOIP_ATTRIBUTION_URL)=' .server.env > .server.env.tmp || true
printf 'GEOIP_PROVIDER=csv\nGEOIP_FILE=ranges.csv\nGEOIP_ATTRIBUTION="IP Geolocation by DB-IP"\nGEOIP_ATTRIBUTION_URL=https://db-ip.com\n' >> .server.env.tmp
mv .server.env.tmp .server.env
chmod 600 .server.env
echo "База за $month установлена: $rows диапазонов. Геолокация включена."
