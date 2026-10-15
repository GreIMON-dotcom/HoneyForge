"""Повторяемая проверка переводов и инвентаризация оставшихся строк."""
from cli_locale import RussianArgumentParser
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from html.parser import HTMLParser

ROOT=Path(__file__).resolve().parents[2]
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
os.chdir(ROOT)


def latin_phrase(value):
    return bool(re.search(r'\b[A-Za-z]{3,} [A-Za-z]{3,}',value)) and not re.search('[А-Яа-яЁё]',value)


def main():
    parser=RussianArgumentParser(description=__doc__)
    parser.add_argument('--node',default='node')
    args=parser.parse_args()
    explained=[]
    unexplained=[]
    def record(file,line,text,reason=None):
        row={'file':str(file).replace('\\','/'),'line':line,'text':text,'reason':reason}
        (explained if reason else unexplained).append(row)

    ui=json.loads(subprocess.check_output([args.node,'tests/scan-ui.cjs'],encoding='utf8'))
    for row in ui:
        reason='Название продукта или техническое обозначение.' if re.fullmatch(r'(?:HoneyForge(?: v[\d.]+)?|H|TCP|HTTP|API)',row['text']) else None
        record(row['file'],row['line'],row['text'],reason)

    class HTMLAudit(HTMLParser):
        def handle_data(self,data):
            value=data.strip()
            if latin_phrase(value):record(self.file,self.getpos()[0],value,'Название продукта и API.' if value=='API HoneyForge' else None)
        def handle_starttag(self,tag,attrs):
            for name,value in attrs:
                if name in {'title','placeholder','aria-label'} and value and latin_phrase(value):record(self.file,self.getpos()[0],value)
    for file in (ROOT/'frontend').glob('*.html'):
        parser=HTMLAudit();parser.file=file.relative_to(ROOT);parser.feed(file.read_text(encoding='utf8'))

    for folder in ['backend/app','agent','honeypots','shared','infrastructure/scripts']:
        for file in (ROOT/folder).glob('*.py'):
            if file.name in {'audit_localization.py','cli_locale.py'}:continue
            tree=ast.parse(file.read_text(encoding='utf8'))
            docstrings={id(node.body[0].value) for node in ast.walk(tree) if isinstance(node,(ast.Module,ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and node.body and isinstance(node.body[0],ast.Expr) and isinstance(node.body[0].value,ast.Constant)}
            for node in ast.walk(tree):
                if not isinstance(node,ast.Constant) or not isinstance(node.value,str) or id(node) in docstrings or not latin_phrase(node.value):continue
                value=node.value
                reason=None
                if re.match(r'\s*(?:SELECT|INSERT|DELETE|CREATE|DROP|PRAGMA|BEGIN)\b',value):reason='Исполняемый SQL; перевод изменил бы поведение.'
                elif re.match(r'(?:import |from |python -c|docker )',value):reason='Фиксированная исполняемая команда, не текст интерфейса.'
                elif file.name=='localization.py':reason='Исходное сообщение библиотеки — ключ сопоставления с русским сообщением.'
                elif file.name=='reporting.py' and value in {'not configured','within validity period','outside validity period'}:reason='Совместимое значение API; интерфейс переводит его через labels.settingValue.'
                elif file.name=='service.py' and value in {'Bad Request','Not Found','Internal Server Error','Service Unavailable'}:reason='Стандартная фраза состояния протокола HTTP; изменение нарушило бы формат ответа.'
                elif file.name=='service.py' and value in {'Laboratory client connected','Synthetic administration login attempt','Viewed synthetic page','Laboratory client sent data'}:reason='Исходное описание записанной телеметрии; сохраняется без преобразования данных.'
                elif file.name=='service.py' and value.strip()=='Login incorrect':reason='Стандартный ответ диалога входа вымышленного Telnet-сервера.'
                elif file.name in {'service.py','insights.py','high.py'} and value in {'Shell command','Telnet login attempt','Sandbox login attempt','Sandbox session closed; reset required','Sandbox input'}:reason='Стабильный маркер события в данных; интерфейс показывает отдельное русское описание.'
                elif file.name=='high.py' and value in {'Worker frame limit','Worker frame count limit','Unexpected worker frame','Worker chunk limit','Session capture limit','Invalid artifact digest','Sandbox is busy'}:reason='Внутренняя диагностика границы sandbox; в пользовательское сообщение попадает тип ошибки, а не эта строка.'
                elif file.name=='sandbox_probe.py' and value in {'Probe frame limit','Shell/capture/UDS probe failed'}:reason='Диагностика проверочного процесса, который не обслуживает пользовательский интерфейс.'
                elif file.name=='shell.py':reason='Ответ или содержимое вымышленной Linux-системы внутри эмулятора. Язык приманки отделён от русского интерфейса управления.'
                elif file.name=='rendering.py' and ('<' in value or '*{box-sizing:' in value):reason='Фрагмент HTML, SVG или CSS сервиса-приманки; имена тегов, атрибутов и свойств не переводятся.'
                elif file.name=='catalog.py' and value=='Linux sandbox':reason='Технический баннер Linux-среды; название сервиса в интерфейсе содержит русское пояснение.'
                elif file.name=='setup.py' and value in {'HoneyForge Local Lab CA','HoneyForge laboratory'}:reason='Техническое имя субъекта сертификата; сохранено для совместимости и идентификации CA.'
                elif file.name=='download_pg.py' and value.startswith('<a href='):reason='Регулярное выражение для страницы официального дистрибутива.'
                elif value.startswith('<') and not re.sub(r'<[^>]*>','',value).strip():reason='HTML-разметка без отображаемого текста.'
                elif file.name=='local_host.py' and value=='not found':reason='Маркер ошибки Docker CLI для проверки существования ресурса; не выводится приложением.'
                record(file.relative_to(ROOT),node.lineno,value,reason)

    dictionary=json.loads((ROOT/'frontend/locales/ru.json').read_text(encoding='utf8'))
    def strings(node):
        if isinstance(node,str):yield node
        elif isinstance(node,dict):
            for value in node.values():yield from strings(value)
    for value in strings(dictionary):
        if '\ufffd' in value:record('frontend/locales/ru.json',1,value)
        if re.search('[A-Za-z]{2,}',value) and not re.search('[А-Яа-яЁё]',value):
            record('frontend/locales/ru.json',1,value,'Общепринятое техническое обозначение.' if value in {'API','HTTP','TCP','TLS','WebSocket','HoneyForge'} else None)
    for file in [ROOT/'README.md',*(ROOT/'docs').glob('*.md')]:
        fenced=False
        for line_number,line in enumerate(file.read_text(encoding='utf8').splitlines(),1):
            if line.strip().startswith('```'):
                fenced=not fenced
                continue
            if fenced:continue
            prose=re.sub(r'`[^`]+`|https?://[^\s)]+|<[^>]+>','',line)
            prose=re.sub(r'\]\([^)]*\)',']',prose)
            if latin_phrase(prose):
                record(file.relative_to(ROOT),line_number,line,'Исходный термин в двуязычном глоссарии.' if file.name=='localization.md' and line.startswith('|') else None)
    report={'unexplained':unexplained,'explained':explained,'translation_strings':len(list(strings(dictionary))),
            'scope':'AST аргументов интерфейса, HTML-текст и атрибуты, строковые константы Python, словарь и проза документации; динамические значения дополнительно проверяются браузерным сценарием ui-localization.cjs.'}
    out=ROOT/'artifacts/localization-audit.json';out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(f'Строк перевода: {report["translation_strings"]}. Объяснённых исключений: {len(explained)}. Необъяснённых строк: {len(unexplained)}.')
    for row in unexplained:print(f'{row["file"]}:{row["line"]}: {row["text"][:200]}')
    return bool(unexplained)


if __name__=='__main__':raise SystemExit(main())
