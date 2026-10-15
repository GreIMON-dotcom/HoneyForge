"""Register a separate host: send only its token hash, store the token in an owner-only file.

Run on the trusted operator computer, then transfer .sandbox.env and public CA cert
to the dedicated VM. Never copy the center's .env, CA private key or database there.
"""
import argparse
import getpass
import hashlib
import ipaddress
import os
from pathlib import Path
import secrets
import ssl
from urllib.parse import urlsplit
import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True, help='HTTPS operator URL of HoneyForge')
    parser.add_argument('--id', default='sandbox-1')
    parser.add_argument('--name', default='Отдельный узел Linux sandbox')
    parser.add_argument('--vpn-ip', required=True, help='Private VPN IPv4 of the center')
    parser.add_argument('--ca', help='CA PEM for the operator endpoint, if it uses a private CA')
    parser.add_argument('--output', default='.sandbox.env')
    args = parser.parse_args()
    origin = urlsplit(args.url)
    if origin.scheme != 'https' or origin.username or origin.password or origin.query or origin.fragment:
        parser.error('Нужен адрес HTTPS без учётных данных и параметров')
    address = ipaddress.ip_address(args.vpn_ip)
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified or address.is_link_local:
        parser.error('Нужен частный IPv4 центра в VPN')
    output = Path(args.output)
    if output.exists():
        parser.error('Файл уже существует; выберите новый --output, чтобы не потерять действующий секрет')
    token = secrets.token_urlsafe(48)
    username, password = input('Пользователь HoneyForge: '), getpass.getpass('Пароль HoneyForge: ')
    context = ssl.create_default_context(cafile=args.ca) if args.ca else ssl.create_default_context()
    with httpx.Client(base_url=args.url.rstrip('/'), verify=context, timeout=20,
                      headers={'X-HoneyForge': '1', 'Origin': f'{origin.scheme}://{origin.netloc}'}) as client:
        client.post('/api/v1/auth/login', json={'username': username, 'password': password}).raise_for_status()
        response = client.post('/api/v1/hosts', json={'id': args.id, 'name': args.name,
            'credential_sha256': hashlib.sha256(token.encode()).hexdigest(), 'max_instances': 4,
            'cpu_budget': 4, 'memory_budget_mb': 4096})
        response.raise_for_status()
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as target:
        target.write(f'SANDBOX_HOST_ID={args.id}\nSANDBOX_CONTROLLER_TOKEN={token}\nCENTER_VPN_IP={address}\n'
                     'PUBLISH_PORTS=8024\nPUBLISH_ADDRESS=127.0.0.1\nDOCKER_SOCKET_GID=0\n')
    print('Узел зарегистрирован. Файл сохранён:', output)


if __name__ == '__main__':
    main()
