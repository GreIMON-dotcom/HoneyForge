from pathlib import Path
import json
import re
import socket
import subprocess
import sys
import yaml
from infrastructure.scripts.isolation import TCP_PROBE

ROOT=Path(__file__).resolve().parents[1]


def test_compose_runs_only_the_control_plane_and_one_restricted_controller():
    config=yaml.safe_load((ROOT/'compose.yaml').read_text(encoding='utf8'))
    services=config['services']
    assert set(services)=={'postgres','migrate','backend','nginx','controller','decoy-network','test-client','notifier'}
    notifier=services['notifier']
    assert notifier['profiles']==['notify'] and notifier['networks']==['management','egress'] and 'ports' not in notifier
    assert 'docker.sock' not in str(notifier) and 'DATABASE_URL' not in notifier['environment'] and 'ADMIN_PASSWORD' not in notifier['environment']
    assert [name for name, service in services.items() if 'egress' in service['networks']]==['notifier']
    assert 'internal' not in config['networks']['egress']
    assert services['decoy-network']['networks']==['decoy','exposed'] and services['decoy-network']['restart']=='no'
    assert services['controller']['environment']['PUBLISH_PORTS']=='${PUBLISH_PORTS:-}'
    assert services['controller']['environment']['PUBLISH_ADDRESS']=='${PUBLISH_ADDRESS:-127.0.0.1}'
    exposed=config['networks']['exposed']['driver_opts']
    assert exposed=={'com.docker.network.bridge.enable_ip_masquerade':'false','com.docker.network.bridge.enable_icc':'false'}
    assert [name for name, service in services.items() if 'exposed' in service['networks']]==['decoy-network']
    assert services['controller']['depends_on']['decoy-network']['condition']=='service_completed_successfully'
    assert set(config['volumes'])=={'database'}
    assert all(config['networks'][name]['internal'] for name in ('database','control','management','decoy'))
    assert [name for name, service in services.items() if 'ingress' in service['networks']] == ['nginx']
    assert config['networks']['ingress']['driver_opts']['com.docker.network.bridge.host_binding_ipv4']=='127.0.0.1'
    assert services['nginx']['ports']==['127.0.0.1:${MANAGEMENT_PORT:-8443}:8443']
    assert [name for name, service in services.items() if 'ports' in service]==['nginx']
    with_socket=[name for name, service in services.items() if 'docker.sock' in str(service.get('volumes',''))]
    assert with_socket==['controller']
    controller=services['controller']
    assert controller['networks']==['management'] and 'ports' not in controller
    assert controller['read_only'] and controller['cap_drop']==['ALL'] and controller['user']=='10001:10001'
    assert controller['security_opt']==['no-new-privileges:true']
    assert 'ADMIN_PASSWORD' not in controller['environment'] and 'DATABASE_URL' not in controller['environment']
    assert 'docker.sock' not in str(services['backend']) and 'docker.sock' not in str(services['nginx'])
    client=services['test-client']
    assert client['networks']==['decoy'] and client['profiles']==['demo'] and 'environment' not in client
    assert services['backend']['depends_on']['migrate']['condition']=='service_completed_successfully'
    assert 'AGENT_LOW_TOKEN' not in str(config) and 'honeypot-low' not in str(config)


def test_nginx_tls_and_endpoint_separation():
    proxy=(ROOT/'infrastructure/nginx/nginx.conf').read_text()
    assert 'listen 8443 ssl' in proxy and 'listen 9443 ssl' in proxy
    assert 'TLSv1.2 TLSv1.3' in proxy
    assert 'client_max_body_size 1m' in proxy
    operator,machine=proxy.split('listen 9443 ssl')
    for prefix in ('/api/v1/agents/','/api/v1/runtime/'):
        assert re.search(r'location\s+' + re.escape(prefix) + r'\s*\{\s*return\s+403;\s*\}', operator)
        assert f'location {prefix} {{\n            proxy_pass' in machine
    assert operator.count('return 403')==2 and 'location / { return 403; }' in machine


def test_isolation_probe_rejects_reachable_target_and_missing_positive_control():
    with socket.socket() as listening, socket.socket() as closed:
        listening.bind(('127.0.0.1', 0))
        listening.listen(4)
        closed.bind(('127.0.0.1', 0))
        for target, expectation, should_pass in [
            (listening, 'open', True), (listening, 'closed', False),
            (closed, 'closed', True), (closed, 'open', False),
        ]:
            result = subprocess.run([sys.executable, '-c', TCP_PROBE,
                                     json.dumps([target.getsockname()]), expectation],
                                    capture_output=True, text=True, timeout=5)
            assert (result.returncode == 0) == should_pass, result.stdout + result.stderr


def test_setup_adds_controller_identity_without_replacing_existing_secrets(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT/'infrastructure/scripts'))
    import setup
    monkeypatch.setattr(setup, 'ROOT', tmp_path)
    (tmp_path/'infrastructure/certs').mkdir(parents=True)
    (tmp_path/'infrastructure/certs/server.crt').write_text('existing')
    legacy='POSTGRES_PASSWORD=keep-me\nADMIN_PASSWORD=keep-me-too\nAGENT_LOW_TOKEN=old\n'
    (tmp_path/'.env').write_text(legacy)
    setup.main()
    upgraded=(tmp_path/'.env').read_text()
    assert upgraded.startswith(legacy) and upgraded.count('CONTROLLER_TOKEN=')==1
    token=upgraded.split('CONTROLLER_TOKEN=')[1].strip()
    assert len(token)>=32
    setup.main()
    assert (tmp_path/'.env').read_text()==upgraded
