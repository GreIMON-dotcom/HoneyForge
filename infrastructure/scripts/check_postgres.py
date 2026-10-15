"""Windows QA using a project-local PostgreSQL cluster bound exclusively to loopback."""
import os
import secrets
import subprocess
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import tempfile
import shutil
import hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'artifacts/postgres'
BASE=Path(tempfile.gettempdir())/('honeyforge-pg-'+hashlib.sha256(str(ROOT).encode()).hexdigest()[:10])
BIN=BASE/'pgsql/bin'
DATA=BASE/'data'


def run(args,**kwargs):
    result=subprocess.run([str(a) for a in args],cwd=ROOT,check=True,**kwargs)
    return result


def main():
    BASE.mkdir(parents=True,exist_ok=True)
    if not BIN.exists():
        shutil.copytree(SOURCE/'pgsql',BASE/'pgsql')
    password_path=BASE/'password.txt'
    if not password_path.exists():
        password_path.write_text(secrets.token_hex(24),encoding='utf8')
        os.chmod(password_path,0o600)
    password=password_path.read_text().strip()
    if not DATA.exists():
        run([BIN/'initdb.exe','-D',DATA,'-U','honeyforge','-A','scram-sha-256','--pwfile',password_path,'--encoding=UTF8','--locale=C'])
    os.environ['PGPASSWORD']=password
    started=False
    try:
        run([BIN/'pg_ctl.exe','-D',DATA,'-l',BASE/'postgres.log','-o','-h 127.0.0.1 -p 55432','-w','start'])
        started=True
        found=subprocess.run([str(BIN/'psql.exe'),'-h','127.0.0.1','-p','55432','-U','honeyforge','-d','postgres','-tAc',"SELECT 1 FROM pg_database WHERE datname='honeyforge_test'"],capture_output=True,text=True,check=True)
        if '1' not in found.stdout:
            run([BIN/'createdb.exe','-h','127.0.0.1','-p','55432','-U','honeyforge','honeyforge_test'])
        url=f'postgresql+asyncpg://honeyforge:{password}@127.0.0.1:55432/honeyforge_test'
        os.environ['DATABASE_URL']=url
        run([BIN/'psql.exe','-h','127.0.0.1','-p','55432','-U','honeyforge','-d','honeyforge_test','-c','DROP SCHEMA public CASCADE; CREATE SCHEMA public;'])
        run([sys.executable,'-m','alembic','upgrade','head'])
        run([sys.executable,'-m','alembic','check'])
        os.environ['TEST_DATABASE_URL']=url
        run([sys.executable,'-m','pytest','-q','--junitxml=artifacts/postgres-tests.xml'])
    finally:
        if started:
            run([BIN/'pg_ctl.exe','-D',DATA,'-m','fast','-w','stop'])
        os.environ.pop('PGPASSWORD',None)


if __name__=='__main__':main()
