#!/bin/sh
set -eu

if [ "$(id -u)" != "0" ]; then
  echo "Нужны права root" >&2
  exit 1
fi

GUARD=/usr/local/sbin/honeyforge-host-guard
cat > "$GUARD" <<'EOF'
#!/bin/sh
# Новые соединения из мостов Docker к самому узлу запрещены. Идемпотентно.
for tool in iptables ip6tables; do
  command -v "$tool" >/dev/null 2>&1 || continue
  "$tool" -C INPUT -i br-+ -m conntrack --ctstate NEW -j DROP 2>/dev/null || \
    "$tool" -I INPUT 1 -i br-+ -m conntrack --ctstate NEW -j DROP
done
EOF
chmod 755 "$GUARD"

cat > /etc/systemd/system/honeyforge-host-guard.service <<EOF
[Unit]
Description=HoneyForge: запрет соединений из контейнеров к узлу
After=network-pre.target
Before=docker.service

[Service]
Type=oneshot
ExecStart=$GUARD
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now honeyforge-host-guard.service >/dev/null
"$GUARD"
echo "Межсетевой экран: соединения из контейнеров к узлу запрещены"
iptables -S INPUT | grep -- '-i br-+' || true

if [ "${1-}" = "--no-ssh" ]; then
  echo "SSH не изменялся (--no-ssh)"
  exit 0
fi

KEYS=/root/.ssh/authorized_keys
if [ ! -s "$KEYS" ] || ! grep -q -E '^(ssh-|ecdsa-|sk-)' "$KEYS"; then
  echo "SSH не изменялся: в $KEYS нет ни одного ключа — иначе доступ к серверу будет потерян" >&2
  exit 0
fi

CONF=/etc/ssh/sshd_config.d/00-honeyforge.conf
cat > "$CONF" <<'EOF'
# HoneyForge: вход только по ключу. Файл читается раньше 50-cloud-init.conf, поэтому имеет приоритет.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
if ! sshd -t; then
  rm -f "$CONF"
  echo "Проверка конфигурации SSH не прошла; изменение отменено" >&2
  exit 1
fi
systemctl reload ssh 2>/dev/null || systemctl reload sshd
echo "SSH: вход только по ключу"
sshd -T | grep -E '^(passwordauthentication|permitrootlogin) '
echo "Текущее подключение не разорвано. Запасной вход — VNC-консоль в панели хостинга."
