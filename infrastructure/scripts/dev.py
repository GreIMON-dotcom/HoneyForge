"""Loopback-only UI development preview. SQLite is NOT the production database."""
import os
import secrets
import subprocess
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def main():
    os.chdir(ROOT)
    if not (ROOT/'.env').exists():
        subprocess.run([sys.executable,'infrastructure/scripts/setup.py'],check=True)
    os.environ['DATABASE_URL']='sqlite+aiosqlite:///./development.db'
    os.environ['COOKIE_SECURE']='false'
    os.environ['ALLOWED_ORIGIN']='http://127.0.0.1:8765'
    os.environ.setdefault('CONTROLLER_TOKEN',secrets.token_urlsafe(48))
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],check=True)
    print('Режим разработки (SQLite, только loopback): http://127.0.0.1:8765',flush=True)
    subprocess.run([sys.executable,'-m','uvicorn','backend.app.main:app','--host','127.0.0.1','--port','8765'],check=True)


if __name__=='__main__':main()
