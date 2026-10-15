from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import String, DateTime, ForeignKey, JSON, UniqueConstraint, Index, Float
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now():
    return datetime.now(timezone.utc)


def uid():
    return str(uuid4())


class Base(DeclarativeBase):
    pass


json_type = JSON().with_variant(JSONB, "postgresql")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str]
    role: Mapped[str] = mapped_column(String(20))
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class LoginSession(Base):
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Profile(Base):
    __tablename__ = "honeypot_profiles"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    spec: Mapped[dict] = mapped_column(json_type)
    version: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class Host(Base):
    """Approved laboratory Docker host served by exactly one deployment controller."""
    __tablename__ = "hosts"
    id: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str]
    management_address: Mapped[str]
    approved: Mapped[bool] = mapped_column(default=False)
    provisioning: Mapped[str] = mapped_column(default="controller", server_default="controller")
    controller_token_hash: Mapped[str | None]
    network: Mapped[str] = mapped_column(default="decoy", server_default="decoy")
    max_instances: Mapped[int] = mapped_column(default=12, server_default="12")
    cpu_budget: Mapped[float] = mapped_column(Float, default=8.0, server_default="8")
    memory_budget_mb: Mapped[int] = mapped_column(default=4096, server_default="4096")
    port_range_start: Mapped[int] = mapped_column(default=8000, server_default="8000")
    port_range_end: Mapped[int] = mapped_column(default=8999, server_default="8999")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metrics: Mapped[dict] = mapped_column(json_type, default=dict, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Honeypot(Base):
    """One independently managed instance. A profile is only the template it was created from."""
    __tablename__ = "honeypots"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="", server_default="")
    tags: Mapped[list] = mapped_column(json_type, default=list, server_default="[]")
    profile_id: Mapped[str] = mapped_column(ForeignKey("honeypot_profiles.id"), index=True)
    profile_version: Mapped[int] = mapped_column(default=1, server_default="1")
    overrides: Mapped[dict] = mapped_column(json_type, default=dict, server_default="{}")
    configuration: Mapped[dict] = mapped_column(json_type, default=dict, server_default="{}")
    update_policy: Mapped[str] = mapped_column(default="manual", server_default="manual")
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    desired_state: Mapped[str] = mapped_column(default="stopped")
    generation: Mapped[int] = mapped_column(default=1)
    applied_generation: Mapped[int] = mapped_column(default=0)
    applied_profile_version: Mapped[int] = mapped_column(default=0, server_default="0")
    ip_address: Mapped[str | None] = mapped_column(String(45))
    status: Mapped[str] = mapped_column(default="draft")
    transition_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    runtime: Mapped[dict] = mapped_column(json_type, default=dict, server_default="{}")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    queue_size: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None]
    last_delivery: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class Agent(Base):
    """Machine identity of one instance's management sidecar."""
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(primary_key=True)
    honeypot_id: Mapped[str | None] = mapped_column(ForeignKey("honeypots.id"), index=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"))
    token_hash: Mapped[str]
    approved: Mapped[bool] = mapped_column(default=False)
    retired: Mapped[bool] = mapped_column(default=False, server_default="false")
    version: Mapped[str] = mapped_column(default="1.0")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class NetworkEndpoint(Base):
    """Reserved laboratory-facing address of an instance.

    The port is unique per host and laboratory network as an addressing policy.
    ``published_port`` is the host port an administrator asked to publish for this
    instance, or NULL (the default): the instance is reachable only inside the lab
    network. Only ports the host controller itself reports as allowed can be set.
    """
    __tablename__ = "network_endpoints"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"))
    network: Mapped[str]
    protocol: Mapped[str] = mapped_column(default="tcp")
    alias: Mapped[str]
    internal_port: Mapped[int]
    published_port: Mapped[int | None]
    allocation_status: Mapped[str] = mapped_column(default="reserved")
    mode: Mapped[str] = mapped_column(default="auto")
    honeypot_id: Mapped[str] = mapped_column(ForeignKey("honeypots.id"), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (UniqueConstraint("host_id", "network", "internal_port", name="uq_endpoint_host_network_port"),
                      UniqueConstraint("host_id", "network", "alias", name="uq_endpoint_host_network_alias"))


class SourceGeo(Base):
    """Enrichment cache for source addresses, kept apart from the raw telemetry it describes."""
    __tablename__ = "source_geo"
    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True)
    scope: Mapped[str] = mapped_column(String(10), default="public")
    country_code: Mapped[str | None] = mapped_column(String(2), index=True)
    country_name: Mapped[str | None]
    city: Mapped[str | None]
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    asn: Mapped[str | None]
    provider: Mapped[str] = mapped_column(default="none")
    enriched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InteractionSession(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    honeypot_id: Mapped[str] = mapped_column(ForeignKey("honeypots.id"))
    session_uid: Mapped[str]
    source_ip: Mapped[str]
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(default=0)
    __table_args__ = (UniqueConstraint("honeypot_id", "session_uid"),)


class Event(Base):
    __tablename__ = "telemetry_events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    event_uid: Mapped[str]
    honeypot_id: Mapped[str] = mapped_column(ForeignKey("honeypots.id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))
    session_id: Mapped[str]
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    source_port: Mapped[int]
    destination_port: Mapped[int]
    protocol: Mapped[str] = mapped_column(String(10), index=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    payload: Mapped[dict] = mapped_column(json_type)
    __table_args__ = (UniqueConstraint("agent_id", "event_uid"), Index("ix_events_hp_type_received", "honeypot_id", "event_type", "received_at"))


class Command(Base):
    __tablename__ = "management_commands"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    honeypot_id: Mapped[str] = mapped_column(ForeignKey("honeypots.id"))
    command_type: Mapped[str]
    generation: Mapped[int]
    status: Mapped[str] = mapped_column(default="pending")
    error: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    honeypot_id: Mapped[str] = mapped_column(ForeignKey("honeypots.id"))
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"))
    profile_id: Mapped[str] = mapped_column(ForeignKey("honeypot_profiles.id"))
    initiated_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    operation: Mapped[str] = mapped_column(default="deploy", server_default="deploy")
    generation: Mapped[int]
    status: Mapped[str] = mapped_column(default="pending")
    runtime_identifier: Mapped[str | None]
    error_message: Mapped[str | None]
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeploymentLog(Base):
    """Ordered record of what the controller and the instance actually did."""
    __tablename__ = "deployment_logs"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    honeypot_id: Mapped[str] = mapped_column(ForeignKey("honeypots.id"), index=True)
    deployment_id: Mapped[str | None] = mapped_column(ForeignKey("deployments.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    level: Mapped[str] = mapped_column(default="info")
    code: Mapped[str]
    details: Mapped[dict] = mapped_column(json_type, default=dict)


class AlertRule(Base):
    __tablename__ = "alert_rules"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    name: Mapped[str]
    enabled: Mapped[bool] = mapped_column(default=True)
    honeypot_id: Mapped[str | None] = mapped_column(ForeignKey("honeypots.id"))
    event_type: Mapped[str]
    threshold: Mapped[int]
    window_seconds: Mapped[int]
    severity: Mapped[str]


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(primary_key=True, default=uid)
    rule_id: Mapped[str] = mapped_column(ForeignKey("alert_rules.id"))
    honeypot_id: Mapped[str] = mapped_column(ForeignKey("honeypots.id"))
    severity: Mapped[str]
    status: Mapped[str] = mapped_column(default="open")
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    details: Mapped[dict] = mapped_column(json_type)


class Audit(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    actor: Mapped[str]
    action: Mapped[str]
    resource: Mapped[str]
    result: Mapped[str] = mapped_column(default="success")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    details: Mapped[dict] = mapped_column(json_type, default=dict)
