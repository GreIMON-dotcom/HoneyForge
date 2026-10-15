"""Download the official EDB PostgreSQL 16 Windows binary archive for local QA."""
import re
import urllib.request
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
from pathlib import Path
import zipfile

root=Path(__file__).resolve().parents[2]/'artifacts'/'postgres'
root.mkdir(parents=True,exist_ok=True)
html=urllib.request.urlopen('https://www.enterprisedb.com/download-postgresql-binaries',timeout=30).read().decode()
section=html.split('Version <!-- -->16.',1)[1].split('Version <!-- -->15.',1)[0]
links=re.findall(r'<a href="(https://sbp\.enterprisedb\.com/getfile\.jsp\?fileid=\d+)"><img alt="([^"]+)"',section)
url=next(url for url,platform in links if 'Windows' in platform)
archive=root/'postgres.zip'
if not archive.exists():
    with urllib.request.urlopen(url,timeout=120) as response,archive.open('wb') as output:
        print('Загрузка официального архива PostgreSQL:',response.url,flush=True)
        import shutil
        shutil.copyfileobj(response,output)
with zipfile.ZipFile(archive) as z:
    selected=[n for n in z.namelist() if n.startswith(('pgsql/bin/','pgsql/lib/','pgsql/share/'))]
    for name in selected:
        target=(root/name).resolve()
        if root.resolve() not in target.parents:
            raise RuntimeError('Недопустимый путь в архиве')
        z.extract(name,root)
print('Переносимый PostgreSQL подготовлен в artifacts/postgres/pgsql. Системная служба не устанавливалась.',flush=True)
