"""Registry of supported honeypot service plugins.

A plugin is trusted application code: an emulator in ``honeypots/`` plus the
declarative defaults below. Administrators instantiate plugins any number of
times through the constructor; they cannot add executable behaviour from the
interface. Adding a protocol means adding an emulator and a registry entry
(see docs/plugins.md).
"""
from dataclasses import dataclass, field
from .contracts import ProfileSpec, SERVICE_FAMILIES
from .sites import STORE_SITE, PORTAL_SITE

RUNTIME_IMAGE = "honeyforge:local"
SCHEMA_VERSION = 1
PLACEHOLDERS = ("{title}", "{description}", "{account}", "{status}")

COMMON_FIELDS = ("description", "enabled", "port", "response_delay_ms", "max_connections")
TELEMETRY_FIELDS = ("telemetry_enabled", "connection_logging", "authentication_logging", "request_logging",
                    "logging_verbosity", "batch_interval", "buffer_limit", "health_interval", "retry_max_seconds")
RESOURCE_FIELDS = ("memory_mb", "cpu_limit")
TCP_FIELDS = ("banner", "banner_encoding", "connection_timeout", "max_input_bytes")
HTTP_FIELDS = ("identity", "site_description", "site_layout", "site_footer", "decoy_accounts", "authentication_mode",
               "status_message", "session_timeout", "login_path", "pages", "routes")

NOTICE = "Разрешённая лабораторная имитация. Используйте только вымышленные данные входа."
LOGIN_FORM = {"type": "form", "action": "/login", "submit_label": "Войти", "fields": [
    {"name": "username", "label": "Тестовое имя пользователя", "kind": "text"},
    {"name": "password", "label": "Вымышленный пароль", "kind": "password"}]}
WELCOME_PAGE = {"title": "{title}", "components": [
    {"type": "heading", "text": "{title}", "level": 1},
    {"type": "paragraph", "text": "Имитируемый сеанс создан. Все отображаемые данные вымышлены."},
    {"type": "links", "items": [{"label": "Панель", "href": "/dashboard"}, {"label": "Состояние сервиса", "href": "/status"}]}]}
DENIED_PAGE = {"title": "{title}", "components": [
    {"type": "heading", "text": "{title}", "level": 1},
    {"type": "paragraph", "text": "Тестовый вход отклонён: используйте настроенную вымышленную учётную запись."},
    {"type": "links", "items": [{"label": "Назад", "href": "/"}]}]}
STATUS_PAGE = {"title": "{title}", "components": [
    {"type": "heading", "text": "Состояние сервиса", "level": 1},
    {"type": "paragraph", "text": "{status}"},
    {"type": "links", "items": [{"label": "Назад", "href": "/"}]}]}

ADMIN_SITE = {
    "login_path": "/",
    "pages": {
        "login": {"title": "{title}", "components": [
            {"type": "heading", "text": "{title}", "level": 1},
            {"type": "paragraph", "text": NOTICE}, LOGIN_FORM,
            {"type": "paragraph", "text": "Тестовая учётная запись: {account}"}]},
        "welcome": WELCOME_PAGE, "denied": DENIED_PAGE, "status": STATUS_PAGE,
        "dashboard": {"title": "{title}", "components": [
            {"type": "heading", "text": "Панель администратора", "level": 1},
            {"type": "status_panel", "title": "Вымышленные узлы", "items": [
                {"label": "Шлюз", "value": "Работает", "state": "ok"},
                {"label": "Хранилище", "value": "Заполнено на 71 %", "state": "warning"},
                {"label": "Резервная копия", "value": "Не выполнялась", "state": "error"}]},
            {"type": "links", "items": [{"label": "Состояние сервиса", "href": "/status"}, {"label": "Выход", "href": "/"}]}]}},
    "routes": [
        {"path": "/", "method": "GET", "response": "page", "page": "login"},
        {"path": "/admin", "method": "GET", "response": "page", "page": "login"},
        {"path": "/login", "method": "POST", "response": "login", "page": "welcome", "failure_page": "denied"},
        {"path": "/dashboard", "method": "GET", "response": "page", "page": "dashboard", "requires_login": True},
        {"path": "/status", "method": "GET", "response": "page", "page": "status"}]}

WEBSITE = {
    "login_path": "/login",
    "pages": {
        "home": {"title": "{title}", "components": [
            {"type": "heading", "text": "{title}", "level": 1},
            {"type": "paragraph", "text": "{description}"},
            {"type": "info_panel", "title": "О площадке", "text": "Учебный сайт лаборатории. Все сведения на страницах вымышлены."},
            {"type": "links", "items": [{"label": "О проекте", "href": "/about"}, {"label": "Контакты", "href": "/contacts"},
                                        {"label": "Вход для сотрудников", "href": "/login"}]}]},
        "about": {"title": "О проекте — {title}", "components": [
            {"type": "heading", "text": "О проекте", "level": 1},
            {"type": "paragraph", "text": "Страница содержит вымышленное описание учебной организации."},
            {"type": "links", "items": [{"label": "На главную", "href": "/"}]}]},
        "contacts": {"title": "Контакты — {title}", "components": [
            {"type": "heading", "text": "Контакты", "level": 1},
            {"type": "info_panel", "title": "Приёмная", "text": "Адрес и телефон вымышлены и не принадлежат реальной организации."},
            {"type": "links", "items": [{"label": "На главную", "href": "/"}]}]},
        "login": {"title": "Вход — {title}", "components": [
            {"type": "heading", "text": "Вход для сотрудников", "level": 1},
            {"type": "paragraph", "text": NOTICE}, LOGIN_FORM]},
        "welcome": WELCOME_PAGE | {"components": WELCOME_PAGE["components"][:2] + [
            {"type": "links", "items": [{"label": "На главную", "href": "/"}]}]},
        "denied": DENIED_PAGE | {"components": DENIED_PAGE["components"][:2] + [
            {"type": "links", "items": [{"label": "Назад", "href": "/login"}]}]}},
    "routes": [
        {"path": "/", "method": "GET", "response": "page", "page": "home"},
        {"path": "/about", "method": "GET", "response": "page", "page": "about"},
        {"path": "/contacts", "method": "GET", "response": "page", "page": "contacts"},
        {"path": "/login", "method": "GET", "response": "page", "page": "login"},
        {"path": "/login", "method": "POST", "response": "login", "page": "welcome", "failure_page": "denied"}]}

JSON_API = {
    "login_path": "/api/v1/login",
    "pages": {},
    "routes": [
        {"path": "/", "method": "GET", "response": "json", "json_body": {"service": "laboratory-api", "version": "1.4.2", "synthetic": True}},
        {"path": "/api/v1/status", "method": "GET", "response": "json", "json_body": {"status": "ok", "nodes": 3, "synthetic": True}},
        {"path": "/api/v1/login", "method": "POST", "response": "login"},
        {"path": "/api/v1/users", "method": "GET", "response": "json", "requires_login": True,
         "json_body": {"users": 0, "synthetic": True}}]}


@dataclass(frozen=True)
class ServicePlugin:
    key: str
    display_name: str
    description: str
    protocol: str
    default_port: int
    event_types: tuple[str, ...]
    capabilities: tuple[str, ...]
    fields: tuple[str, ...]
    defaults: dict = field(default_factory=dict)
    image: str = RUNTIME_IMAGE
    command: tuple[str, ...] = ("python", "-m", "honeypots.service")
    health_check: str = "Процесс приманки каждую секунду подтверждает, что слушающий сокет открыт на назначенном порту."
    schema_version: int = SCHEMA_VERSION

    @property
    def emulator(self) -> str:
        return SERVICE_FAMILIES[self.key][0]

    @property
    def interaction_level(self) -> str:
        return SERVICE_FAMILIES[self.key][1]

    def default_spec(self, name: str = "Новый профиль") -> dict:
        """Complete validated configuration the constructor starts from."""
        return ProfileSpec.model_validate({"name": name, "service_key": self.key, "port": self.default_port,
                                           **self.defaults}).model_dump()

    def view(self) -> dict:
        return {"id": self.key, "key": self.key, "display_name": self.display_name, "description": self.description,
                "emulator": self.emulator, "interaction_level": self.interaction_level, "protocol": self.protocol,
                "default_port": self.default_port, "image_reference": self.image, "config_schema_version": self.schema_version,
                "event_types": list(self.event_types), "capabilities": list(self.capabilities),
                "fields": list(self.fields), "health_check": self.health_check, "is_enabled": True,
                "runtime": {"memory_mb": self.defaults.get("memory_mb", 128), "cpu_limit": self.defaults.get("cpu_limit", 0.5),
                            "containers": 3 if self.key == 'linux-sandbox' else 2, "user": "10001:10001",
                            "requires_dedicated_node": self.key == 'linux-sandbox',
                            "worker_memory_mb": 256 if self.key == 'linux-sandbox' else 0,
                            "worker_cpu": 0.5 if self.key == 'linux-sandbox' else 0}}


HTTP_EVENTS = ("connection", "http_request", "authentication_attempt", "navigation")
SHELL_FIELDS = ("banner", "banner_encoding", "hostname", "authentication_mode", "decoy_accounts",
                "connection_timeout", "max_input_bytes", "max_commands")
SHARED = COMMON_FIELDS + TELEMETRY_FIELDS + RESOURCE_FIELDS

PLUGINS = {plugin.key: plugin for plugin in (
    ServicePlugin(
        key="tcp-banner", display_name="TCP-сервис с баннером",
        description="Принимает подключения, отправляет настраиваемую строку приветствия и записывает адрес клиента. "
                    "При необходимости фиксирует ограниченный объём присланных данных. Команды не выполняются.",
        protocol="TCP", default_port=8022, event_types=("connection", "data_received"),
        capabilities=("Настраиваемый баннер и кодировка", "Ограничение времени соединения",
                      "Запись первых байтов клиента", "Ограничение числа соединений"),
        fields=SHARED + TCP_FIELDS, defaults={"banner": "SSH-2.0-HoneyForge_Lab"}),
    ServicePlugin(
        key="http-admin", display_name="HTTP-панель администратора",
        description="Имитация страницы входа в панель управления с вымышленными учётными записями, "
                    "сеансом и закрытым разделом. Пароли не сохраняются.",
        protocol="HTTP", default_port=8080, event_types=HTTP_EVENTS,
        capabilities=("Имитация входа", "Вымышленные учётные записи", "Закрытые разделы по сеансу",
                      "Конструктор страниц и маршрутов"),
        fields=SHARED + HTTP_FIELDS, defaults={"identity": "Лабораторная панель управления", **ADMIN_SITE}),
    ServicePlugin(
        key="http-site", display_name="HTTP-сайт",
        description="Статический сайт из безопасных компонентов: заголовки, тексты, ссылки, информационные панели "
                    "и необязательная форма входа.",
        protocol="HTTP", default_port=8080, event_types=HTTP_EVENTS,
        capabilities=("Конструктор страниц и маршрутов", "Навигация между страницами", "Необязательная форма входа"),
        fields=SHARED + HTTP_FIELDS,
        defaults={"identity": "Лабораторный сайт", "site_description": "Учебная площадка лаборатории.", **WEBSITE}),
    ServicePlugin(
        key="http-api", display_name="HTTP API с ответами JSON",
        description="Имитация программного интерфейса: маршруты возвращают заранее заданные ответы JSON, "
                    "маршрут входа записывает попытки аутентификации.",
        protocol="HTTP", default_port=8080, event_types=HTTP_EVENTS,
        capabilities=("Заданные ответы JSON и коды состояния", "Имитация входа через JSON или форму",
                      "Маршруты, требующие сеанса"),
        fields=SHARED + HTTP_FIELDS, defaults={"identity": "Лабораторный API", **JSON_API}),
    ServicePlugin(
        key="http-store", display_name="Интернет-магазин одежды (заготовка)",
        description="Готовый сайт магазина: главная с баннером и товарами, каталог, скидки, страницы товаров, корзина, "
                    "доставка, контакты и вход в личный кабинет. Название, тексты и товары меняются в конструкторе страниц. "
                    "Оплата и регистрация не имитируются: личные и платёжные данные сайт не запрашивает.",
        protocol="HTTP", default_port=8080, event_types=HTTP_EVENTS,
        capabilities=("Оформление интернет-магазина с меню и подвалом", "Сетка товаров с рисунками", "Страницы товаров и корзина",
                      "Вход в личный кабинет с записью попыток", "Полностью редактируется в конструкторе"),
        fields=SHARED + HTTP_FIELDS, defaults=STORE_SITE),
    ServicePlugin(
        key="http-portal", display_name="Портал сотрудников (заготовка)",
        description="Готовый внутренний портал компании: главная с новостями, заявки в службу поддержки, документы "
                    "за входом и страница входа. Название и тексты меняются в конструкторе страниц.",
        protocol="HTTP", default_port=8080, event_types=HTTP_EVENTS,
        capabilities=("Оформление корпоративного портала", "Новости и разделы карточками", "Закрытые разделы по сеансу",
                      "Вход сотрудника с записью попыток", "Полностью редактируется в конструкторе"),
        fields=SHARED + HTTP_FIELDS, defaults=PORTAL_SITE),
    ServicePlugin(
        key="telnet-shell", display_name="Telnet-оболочка Linux",
        description="Вход по Telnet и командная оболочка вымышленного сервера Linux: файловая система, сведения о системе "
                    "и ответы команд берутся из встроенной таблицы. Записываются попытки входа и каждая введённая команда. "
                    "Команды не выполняются, файлы не загружаются, пароли не сохраняются.",
        protocol="TCP", default_port=8023, event_types=("connection", "authentication_attempt", "data_received"),
        capabilities=("Имитация входа с вымышленными учётными записями", "Интерактивная оболочка с историей команд сеанса",
                      "Вымышленная файловая система и сведения о системе", "Запись попыток загрузки и запуска программ",
                      "Ограничение числа команд и времени сеанса"),
        fields=SHARED + SHELL_FIELDS,
        defaults={"banner": "Ubuntu 22.04.4 LTS", "banner_encoding": "ascii", "hostname": "srv-01",
                  "decoy_accounts": ["root", "admin"], "authentication_mode": "accept-all",
                  "connection_timeout": 180, "max_input_bytes": 256, "max_commands": 40}),
    ServicePlugin(
        key='linux-sandbox', display_name='Linux sandbox: реальная оболочка',
        description='Настоящий Bash на отдельном узле VM/VPS. Одноразовый контейнер gVisor без сети; '
                    'ввод и вывод, процессы, сетевые вызовы и небольшие созданные файлы записываются через внешний шлюз. '
                    'После сеанса контейнер пересоздаётся. Требуется отдельно подготовленный узел sandbox.',
        protocol='TCP', default_port=8024,
        event_types=('connection', 'authentication_attempt', 'data_received'),
        capabilities=('Реальное выполнение команд в Linux', 'Запись ввода и вывода сеанса',
                      'Наблюдение exec/connect через strace', 'Файлы до 64 КиБ: содержимое и SHA-256',
                      'Нет сетевого интерфейса у оболочки', 'Пересоздание после сеанса и по таймеру'),
        fields=SHARED + SHELL_FIELDS,
        defaults={'banner': 'Linux sandbox', 'hostname': 'sandbox', 'decoy_accounts': ['lab'],
                  'authentication_mode': 'accept-all', 'connection_timeout': 180, 'max_commands': 40,
                  'max_input_bytes': 256, 'max_connections': 1, 'logging_verbosity': 'detailed'}),
)}


def plugin_for(key: str) -> ServicePlugin:
    return PLUGINS[key]


def site_definition(spec: ProfileSpec) -> tuple[dict, list]:
    """Pages and routes an HTTP instance serves; profiles without routes use the plugin template."""
    source = spec if spec.routes else ProfileSpec.model_validate(PLUGINS[spec.service_key].default_spec())
    return source.pages, source.routes
