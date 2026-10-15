"""Package only non-ignored source files, never local credentials or runtime data."""
import hashlib
import json
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
from pathlib import Path
import subprocess
import zipfile

root=Path(__file__).resolve().parents[2]
result=subprocess.run(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root,capture_output=True,check=True)
paths=sorted(set(p.decode('utf8') for p in result.stdout.split(b'\0') if p))
output=root/'artifacts/honeyforge-source.zip'
output.parent.mkdir(exist_ok=True)
manifest={}
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
    for name in paths:
        source=root/name
        parts=Path(name).parts
        if any(p in {'.env','.lab','.venv','.git','artifacts','__pycache__'} for p in parts):
            raise RuntimeError('Секретный или служебный путь не должен попадать в архив: '+name)
        if source.suffix in {'.key','.crt','.db'}:
            raise RuntimeError('Секретный или служебный файл не должен попадать в архив: '+name)
        data=source.read_bytes()
        manifest[name]=hashlib.sha256(data).hexdigest()
        archive.writestr('honeyforge/'+name,data)
    archive.writestr('honeyforge/SOURCE-MANIFEST.json',json.dumps(manifest,indent=2))
print(f'В архив {output.name} включено файлов исходного кода: {len(paths)}. Секреты и рабочие данные исключены.')
