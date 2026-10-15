"""Русские сообщения проверки данных без изменения машинных полей и правил."""
import json
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


def validation_message(error):
    kind, context = error['type'], error.get('ctx', {})
    if kind == 'missing':
        return 'Обязательное поле не заполнено'
    if kind in {'string_too_short', 'too_short'}:
        return f"Минимальная длина — {context.get('min_length')}"
    if kind in {'string_too_long', 'too_long'}:
        return f"Максимальная длина — {context.get('max_length')}"
    for code, symbol in [('greater_than_equal', '≥'), ('greater_than', '>'), ('less_than_equal', '≤'), ('less_than', '<')]:
        if kind == code:
            value = context.get({'greater_than_equal':'ge','greater_than':'gt','less_than_equal':'le','less_than':'lt'}[code])
            return f'Значение должно быть {symbol} {value}'
    if kind == 'value_error':
        message = str(context.get('error', ''))
        return message if any('\u0400' <= c <= '\u04ff' for c in message) else 'Недопустимое значение'
    return {
        'int_parsing':'Введите целое число', 'int_type':'Ожидается целое число',
        'float_parsing':'Введите число', 'float_type':'Ожидается число',
        'bool_parsing':'Ожидается логическое значение', 'bool_type':'Ожидается логическое значение',
        'string_type':'Ожидается строка', 'string_pattern_mismatch':'Значение не соответствует допустимому формату',
        'literal_error':'Выберите одно из допустимых значений', 'extra_forbidden':'Дополнительное поле не разрешено',
        'json_invalid':'Некорректный JSON', 'date_from_datetime_parsing':'Некорректная дата',
        'datetime_from_date_parsing':'Некорректные дата и время', 'ip_any_address':'Некорректный IP-адрес',
        'union_tag_invalid':'Неподдерживаемый вариант данных', 'union_tag_not_found':'Не указан тип данных',
    }.get(kind, 'Проверьте значение поля')


def install_localization(app):
    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exception):
        original = await request_validation_exception_handler(request, exception)
        body = json.loads(original.body)
        for error, raw_error in zip(body['detail'], exception.errors()):
            error['msg'] = validation_message(raw_error)
        return JSONResponse(status_code=original.status_code, content=body)

    @app.exception_handler(HTTPException)
    async def http_error(request, exception):
        detail = {'Not Found':'Ресурс не найден','Method Not Allowed':'Метод не разрешён'}.get(exception.detail, exception.detail) if isinstance(exception.detail,str) else exception.detail
        return JSONResponse(status_code=exception.status_code, content={'detail':detail}, headers=exception.headers)

    def localized_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(title=app.title, version=app.version, routes=app.routes,
                             description='API управления ловушками, телеметрией и разрешёнными узлами лаборатории HoneyForge. Машинные идентификаторы и значения перечислений передаются без перевода.')
        for operations in schema['paths'].values():
            for operation in operations.values():
                if not isinstance(operation,dict):
                    continue
                operation.setdefault('description', operation.get('summary','Операция API') + '. Параметры и форматы данных приведены в схеме ниже.')
                for response in operation.get('responses',{}).values():
                    response['description'] = {'Successful Response':'Успешный ответ','Validation Error':'Ошибка проверки данных'}.get(response.get('description'),response.get('description'))
        def captions(node):
            if isinstance(node,dict):
                for name, prop in node.get('properties',{}).items():
                    if isinstance(prop,dict) and 'title' in prop:
                        prop['title'] = f'Поле «{name}»'
                if 'parameters' in node:
                    for parameter in node['parameters']:
                        if 'title' in parameter.get('schema',{}):
                            parameter['schema']['title'] = f"Параметр «{parameter['name']}»"
                for value in node.values():
                    captions(value)
            elif isinstance(node,list):
                for value in node:
                    captions(value)
        captions(schema)
        app.openapi_schema = schema
        return schema
    app.openapi = localized_openapi
