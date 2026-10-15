#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Нужен root на отдельном узле sandbox' >&2; exit 1; }
center="${1:?Укажите частный IPv4 центра}"
python3 - "$center" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
assert ip.version == 4 and ip.is_private and not (ip.is_loopback or ip.is_unspecified or ip.is_link_local), 'Expected private VPN IPv4'
PY
iptables -w -nL DOCKER-USER >/dev/null
iptables -w -N HF-SANDBOX 2>/dev/null || true
iptables -w -F HF-SANDBOX
iptables -w -A HF-SANDBOX -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -w -A HF-SANDBOX -i hfh-mgmt -d "$center" -p tcp --dport 9443 -j RETURN
iptables -w -A HF-SANDBOX -i hfh+ -j DROP
iptables -w -A HF-SANDBOX -j RETURN
iptables -w -C DOCKER-USER -j HF-SANDBOX 2>/dev/null || iptables -w -I DOCKER-USER 1 -j HF-SANDBOX
iptables -w -C INPUT -i hfh+ -m conntrack --ctstate NEW -j REJECT 2>/dev/null || \
  iptables -w -I INPUT 1 -i hfh+ -m conntrack --ctstate NEW -j REJECT
mkdir -p /etc/honeyforge
python3 - "$center" <<'PY'
import json, pathlib, sys
target = pathlib.Path('/etc/honeyforge/sandbox-guard.json')
target.write_text(json.dumps({'policy': 'honeyforge-networkless-v1', 'center_vpn_ip': sys.argv[1],
    'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))
target.chmod(0o444)
PY
printf '%s\n' 'Правила sandbox применены. Настройте их восстановление после перезагрузки перед публикацией порта.'
