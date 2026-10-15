"""Versioned contracts shared by the collector, agent, controller and isolated services.

Everything an administrator can configure is declarative data validated here.
No field is ever interpreted as code, a template expression or a command.
"""
import json
import re
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address
from typing import Literal, Annotated, Union
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

SERVICE_KEYS = ("tcp-banner", "http-admin", "http-site", "http-api", "telnet-shell", "http-store", "http-portal", "linux-sandbox")
SERVICE_FAMILIES = {"tcp-banner": ("tcp", "low"), "http-admin": ("http", "medium"),
                    "http-site": ("http", "medium"), "http-api": ("http", "medium"),
                    "telnet-shell": ("tcp", "medium"),
                    "http-store": ("http", "medium"), "http-portal": ("http", "medium"),
                    "linux-sandbox": ("tcp", "high")}
GARMENTS = ("tshirt", "hoodie", "jeans", "dress", "jacket", "sneakers", "cap", "bag")
COLORS = ("black", "white", "grey", "beige", "navy", "blue", "green", "olive", "red", "pink", "brown")
EVENT_TYPES = ("connection", "data_received", "http_request", "authentication_attempt", "navigation")
RESERVED_PATH_PREFIX = "/static/"
MAX_SPEC_BYTES = 65536

PATH_PATTERN = r"^/[A-Za-z0-9._~/-]{0,119}$"
RoutePath = Annotated[str, Field(pattern=PATH_PATTERN)]
PageKey = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")]


def safe_path(value: str) -> str:
    if ".." in value or "//" in value:
        raise ValueError("Путь не должен содержать «..» и повторяющиеся косые черты")
    if value.startswith(RESERVED_PATH_PREFIX) or value == RESERVED_PATH_PREFIX.rstrip("/"):
        raise ValueError("Путь /static/ зарезервирован для служебных файлов эмулятора")
    return value


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Heading(Strict):
    type: Literal["heading"]
    text: str = Field(min_length=1, max_length=200)
    level: int = Field(default=1, ge=1, le=3)


class Paragraph(Strict):
    type: Literal["paragraph"]
    text: str = Field(min_length=1, max_length=2000)


class FormInput(Strict):
    name: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_]{0,39}$")
    label: str = Field(min_length=1, max_length=80)
    kind: Literal["text", "password"] = "text"


class Form(Strict):
    type: Literal["form"]
    action: RoutePath
    submit_label: str = Field(default="Войти", min_length=1, max_length=40)
    fields: list[FormInput] = Field(min_length=1, max_length=8)

    @field_validator("action")
    @classmethod
    def action_path(cls, value):
        return safe_path(value)


class LinkItem(Strict):
    label: str = Field(min_length=1, max_length=80)
    href: RoutePath

    @field_validator("href")
    @classmethod
    def local_path(cls, value):
        return safe_path(value)


class Links(Strict):
    type: Literal["links"]
    items: list[LinkItem] = Field(min_length=1, max_length=12)


class InfoPanel(Strict):
    type: Literal["info_panel"]
    title: str = Field(min_length=1, max_length=120)
    text: str = Field(default="", max_length=2000)


class StatusItem(Strict):
    label: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=120)
    state: Literal["ok", "warning", "error"] = "ok"


class StatusPanel(Strict):
    type: Literal["status_panel"]
    title: str = Field(min_length=1, max_length=120)
    items: list[StatusItem] = Field(min_length=1, max_length=12)


class Hero(Strict):
    type: Literal["hero"]
    title: str = Field(min_length=1, max_length=120)
    text: str = Field(default="", max_length=400)
    button_label: str = Field(default="", max_length=40)
    button_href: RoutePath = "/"

    @field_validator("button_href")
    @classmethod
    def local_path(cls, value):
        return safe_path(value)


class ProductItem(Strict):
    name: str = Field(min_length=1, max_length=80)
    price: str = Field(min_length=1, max_length=40)
    note: str = Field(default="", max_length=30)
    kind: Literal[GARMENTS] = "tshirt"
    color: Literal[COLORS] = "black"
    href: RoutePath = "/"

    @field_validator("href")
    @classmethod
    def local_path(cls, value):
        return safe_path(value)


class Products(Strict):
    type: Literal["products"]
    title: str = Field(default="", max_length=120)
    items: list[ProductItem] = Field(min_length=1, max_length=12)


class CardItem(Strict):
    title: str = Field(min_length=1, max_length=80)
    text: str = Field(default="", max_length=300)


class Cards(Strict):
    type: Literal["cards"]
    title: str = Field(default="", max_length=120)
    items: list[CardItem] = Field(min_length=1, max_length=8)


Component = Annotated[Union[Heading, Paragraph, Form, Links, InfoPanel, StatusPanel, Hero, Products, Cards], Field(discriminator="type")]


class Page(Strict):
    title: str = Field(min_length=1, max_length=120)
    components: list[Component] = Field(default_factory=list, max_length=30)


class Route(Strict):
    path: RoutePath
    method: Literal["GET", "POST"] = "GET"
    response: Literal["page", "json", "login"] = "page"
    page: PageKey | None = None
    failure_page: PageKey | None = None
    json_body: dict[str, str | int | bool] | None = Field(default=None, max_length=20)
    status: Literal[200, 201, 400, 401, 403, 404, 500, 503] = 200
    requires_login: bool = False
    log: bool = True

    @field_validator("path")
    @classmethod
    def route_path(cls, value):
        return safe_path(value)

    @model_validator(mode="after")
    def consistent(self):
        if self.response == "page" and not self.page:
            raise ValueError("Для ответа страницей укажите страницу")
        if self.response == "json" and self.json_body is None:
            raise ValueError("Для ответа JSON укажите содержимое ответа")
        if self.response == "login" and self.method != "POST":
            raise ValueError("Имитация входа поддерживает только метод POST")
        return self


class ProfileSpec(Strict):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=1000)
    service_key: Literal[SERVICE_KEYS] = "tcp-banner"
    interaction_level: Literal["low", "medium", "high"] = "low"
    service_type: Literal["tcp", "http"] = "tcp"
    enabled: bool = True
    listen_address: Literal["0.0.0.0"] = "0.0.0.0"
    port: int = Field(default=8022, ge=1024, le=65535)
    banner: str = Field(default="SSH-2.0-HoneyForge_Lab", max_length=200)
    banner_encoding: Literal["utf-8", "ascii", "latin-1"] = "utf-8"
    connection_timeout: int = Field(default=12, ge=1, le=600)
    max_input_bytes: int = Field(default=0, ge=0, le=4096)
    hostname: str = Field(default="srv-01", pattern=r"^[a-z0-9][a-z0-9-]{0,30}$")
    max_commands: int = Field(default=40, ge=1, le=200)
    identity: str = Field(default="Лабораторная панель управления", max_length=80)
    site_description: str = Field(default="", max_length=300)
    decoy_accounts: list[Annotated[str, Field(pattern=r'^[a-zA-Z0-9_.-]{1,80}$')]] = Field(
        default_factory=lambda: ['synthetic_operator', 'synthetic'], min_length=1, max_length=10)
    authentication_mode: Literal['accept-all', 'configured-accounts'] = 'accept-all'
    status_message: str = Field(default='Лабораторный шлюз · вымышленные данные · нет производственных подключений', max_length=1000)
    session_timeout: int = Field(default=1800, ge=60, le=86400)
    login_path: RoutePath = "/"
    site_layout: Literal["plain", "store", "portal"] = "plain"
    site_footer: str = Field(default="", max_length=300)
    pages: dict[PageKey, Page] = Field(default_factory=dict, max_length=12)
    routes: list[Route] = Field(default_factory=list, max_length=24)
    telemetry_enabled: bool = True
    logging_verbosity: Literal['metadata', 'detailed'] = 'detailed'
    response_delay_ms: int = Field(default=0, ge=0, le=2000)
    connection_logging: bool = True
    authentication_logging: bool = True
    request_logging: bool = True
    batch_interval: int = Field(default=3, ge=1, le=30)
    buffer_limit: int = Field(default=50000, ge=100, le=1000000)
    health_interval: int = Field(default=5, ge=1, le=15)
    retry_max_seconds: int = Field(default=30, ge=3, le=120)
    max_connections: int = Field(default=64, ge=1, le=256)
    network: Literal["isolated-lab"] = "isolated-lab"
    outbound_policy: Literal["deny"] = "deny"
    memory_mb: int = Field(default=128, ge=64, le=256)
    cpu_limit: float = Field(default=0.5, ge=0.1, le=1)

    @model_validator(mode="before")
    @classmethod
    def derive_service(cls, value):
        """Stored profiles created before the catalog carry only the emulator family."""
        if not isinstance(value, dict):
            return value
        value = dict(value)
        key = value.get("service_key")
        if key == 'telnet-shell' and value.get('interaction_level') == 'high':
            value['interaction_level'] = 'medium'
        if key in SERVICE_FAMILIES:
            family, level = SERVICE_FAMILIES[key]
            value.setdefault("service_type", family)
            value.setdefault("interaction_level", level)
        elif key is None:
            family = value.get("service_type")
            if family is None and value.get("interaction_level") == "medium":
                family = "http"
            value["service_key"] = "http-admin" if family == "http" else "tcp-banner"
        return value

    @model_validator(mode="after")
    def compatible(self):
        if SERVICE_FAMILIES[self.service_key] != (self.service_type, self.interaction_level):
            raise ValueError("Тип сервиса не соответствует семейству эмулятора и уровню взаимодействия")
        if self.service_key == 'linux-sandbox':
            if self.max_connections != 1:
                raise ValueError('Sandbox допускает только один одновременный сеанс')
            if not self.telemetry_enabled or not self.connection_logging or not self.authentication_logging or self.logging_verbosity != 'detailed':
                raise ValueError('Для sandbox обязательны полная запись сеанса и телеметрия')
        if "\r" in self.banner or "\n" in self.banner:
            raise ValueError("Баннер должен занимать одну строку")
        try:
            self.banner.encode(self.banner_encoding)
        except UnicodeEncodeError:
            raise ValueError("Баннер нельзя представить в выбранной кодировке")
        safe_path(self.login_path)
        if (self.routes or self.pages) and self.service_type != "http":
            raise ValueError("Страницы и маршруты поддерживает только HTTP-сервис")
        seen = set()
        for route in self.routes:
            key = (route.method, route.path)
            if key in seen:
                raise ValueError(f"Маршрут {route.method} {route.path} указан несколько раз")
            seen.add(key)
            for page in (route.page, route.failure_page):
                if page and page not in self.pages:
                    raise ValueError(f"Маршрут {route.path} ссылается на отсутствующую страницу «{page}»")
        if len(json.dumps(self.model_dump(), ensure_ascii=False).encode()) > MAX_SPEC_BYTES:
            raise ValueError("Конфигурация превышает допустимый размер")
        return self


FIXED_FIELDS = frozenset({"name", "service_key", "service_type", "interaction_level", "listen_address",
                          "network", "outbound_policy", "port"})
OVERRIDABLE_FIELDS = frozenset(ProfileSpec.model_fields) - FIXED_FIELDS


def effective_configuration(profile_spec: dict, overrides: dict, port: int) -> dict:
    """Merge a reusable profile with one instance's own settings and its reserved port."""
    unknown = set(overrides) - OVERRIDABLE_FIELDS
    if unknown:
        raise ValueError("Эти параметры нельзя переопределить для экземпляра: " + ", ".join(sorted(unknown)))
    return ProfileSpec.model_validate({**profile_spec, **overrides, "port": port}).model_dump()


class EventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_uid: UUID
    honeypot_id: UUID
    session_id: UUID
    timestamp: datetime
    source_ip: str
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=1, le=65535)
    protocol: Literal["TCP", "HTTP"]
    event_type: Literal["connection", "data_received", "http_request", "authentication_attempt", "navigation"]
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    payload: dict[str, str | int | bool] = Field(default_factory=dict)

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value))

    @field_validator("timestamp")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("Временная метка должна содержать часовой пояс и не должна быть в будущем")
        return value.astimezone(timezone.utc)

    @field_validator("payload")
    @classmethod
    def limited_payload(cls, value):
        allowed = {"summary", "path", "method", "username", "result", "user_agent",
                   "status", "bytes_received", "input_preview", "stream", "data", "encoding",
                   "artifact_path", "sha256", "artifact_size", "offset"}
        if set(value) - allowed or len(json.dumps(value)) > 4096:
            raise ValueError("Принимаются только явно разрешённые поля телеметрии с установленными ограничениями")
        if 'data' in value:
            import base64
            import binascii
            if value.get('encoding') != 'base64' or not isinstance(value['data'], str):
                raise ValueError('Некорректная кодировка сеанса sandbox')
            try:
                if len(base64.b64decode(value['data'], validate=True)) > 1024:
                    raise ValueError('Превышен размер фрагмента сеанса')
            except binascii.Error:
                raise ValueError('Некорректный фрагмент сеанса')
        return value


class EventBatch(BaseModel):
    events: list[EventInput] = Field(max_length=200)


class AssignedConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    assigned: Literal[True]
    honeypot_id: UUID
    generation: int = Field(ge=1)
    profile_version: int = Field(ge=1)
    desired_state: Literal["running", "stopped"]
    spec: ProfileSpec


class UnassignedConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    assigned: Literal[False]


configuration_adapter = TypeAdapter(Annotated[
    AssignedConfiguration | UnassignedConfiguration, Field(discriminator="assigned")])


def validate_configuration(value: dict) -> dict:
    """Validate the envelope before replacing a durable working configuration."""
    return configuration_adapter.validate_python(value).model_dump(mode="json")


def printable_preview(data: bytes, limit: int = 200) -> str:
    """Bounded, printable rendering of client input; control bytes never reach storage."""
    return re.sub(r"[^\x20-\x7e]", ".", data[:limit].decode("latin-1"))
