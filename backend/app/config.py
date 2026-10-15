from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+asyncpg://honeyforge@postgres/honeyforge"
    admin_username: str = "admin"
    admin_password: str = ""
    session_hours: int = 8
    cookie_secure: bool = True
    allowed_origin: str = "https://localhost:8443"
    controller_host_id: str = "lab-docker"
    controller_token: str = ""
    heartbeat_timeout: int = 45
    operation_timeout: int = 180
    notifier_token: str = ""
    retention_days: int = 30
    bootstrap_lab: bool = True
    geoip_provider: str = "none"
    geoip_database: str = ""
    geoip_ttl_days: int = 30
    geoip_max_rows: int = 5000000
    geoip_attribution: str = ""
    geoip_attribution_url: str = ""
    tls_certificate_file: str = ''


@lru_cache
def settings() -> Settings:
    return Settings()
