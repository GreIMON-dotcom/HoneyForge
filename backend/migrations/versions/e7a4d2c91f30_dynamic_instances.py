"""Replace the two fixed slots with dynamically created honeypot instances.

Schema: instances own their configuration, endpoint and agent; hosts become
capacity pools served by a deployment controller. Data: every existing honeypot
is kept with its identifier, so its telemetry, sessions, alerts and audit
history stay attached. It is moved to the controller-managed laboratory host
and re-created there as a regular dynamic instance. Slot agents are retired but
kept as the recorded origin of historical events. Nothing is deleted from
telemetry_events, audit_logs, users or honeypot_profiles.
"""
import json
import uuid
from datetime import datetime, timezone
from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision = "e7a4d2c91f30"
down_revision = "c51aa2fc901d"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql")
TIME = sa.DateTime(timezone=True)
LAB_HOST = "lab-docker"
NAMING = {"uq": "uq_%(table_name)s_%(column_0_name)s"}


def empty(kind):
    return sa.text("'{}'" if kind is dict else "'[]'")


def upgrade():
    bind = op.get_bind()
    postgres = bind.dialect.name == "postgresql"
    epoch = sa.text("'1970-01-01 00:00:00+00'")

    with op.batch_alter_table("hosts") as batch:
        batch.add_column(sa.Column("controller_token_hash", sa.String(), nullable=True))
        batch.add_column(sa.Column("network", sa.String(), nullable=False, server_default="decoy"))
        batch.add_column(sa.Column("max_instances", sa.Integer(), nullable=False, server_default="12"))
        batch.add_column(sa.Column("cpu_budget", sa.Float(), nullable=False, server_default="8"))
        batch.add_column(sa.Column("memory_budget_mb", sa.Integer(), nullable=False, server_default="4096"))
        batch.add_column(sa.Column("port_range_start", sa.Integer(), nullable=False, server_default="8000"))
        batch.add_column(sa.Column("port_range_end", sa.Integer(), nullable=False, server_default="8999"))
        batch.add_column(sa.Column("last_seen", TIME, nullable=True))
        batch.add_column(sa.Column("metrics", JSON, nullable=False, server_default=empty(dict)))
        batch.drop_column("service_type")

    if postgres:
        op.drop_constraint("honeypots_host_id_key", "honeypots", type_="unique")
        op.drop_constraint("agents_host_id_key", "agents", type_="unique")
    with op.batch_alter_table("honeypots", naming_convention=NAMING) as batch:
        if not postgres:
            batch.drop_constraint("uq_honeypots_host_id", type_="unique")
        batch.add_column(sa.Column("description", sa.String(length=1000), nullable=False, server_default=""))
        batch.add_column(sa.Column("tags", JSON, nullable=False, server_default=empty(list)))
        batch.add_column(sa.Column("profile_version", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("overrides", JSON, nullable=False, server_default=empty(dict)))
        batch.add_column(sa.Column("configuration", JSON, nullable=False, server_default=empty(dict)))
        batch.add_column(sa.Column("update_policy", sa.String(), nullable=False, server_default="manual"))
        batch.add_column(sa.Column("transition_at", TIME, nullable=True))
        batch.add_column(sa.Column("runtime", JSON, nullable=False, server_default=empty(dict)))
        batch.add_column(sa.Column("updated_at", TIME, nullable=False, server_default=epoch))
        batch.create_index("ix_honeypots_host_id", ["host_id"])
        batch.create_index("ix_honeypots_profile_id", ["profile_id"])

    with op.batch_alter_table("agents", naming_convention=NAMING) as batch:
        if not postgres:
            batch.drop_constraint("uq_agents_host_id", type_="unique")
        batch.alter_column("host_id", existing_type=sa.String(), nullable=True)
        batch.add_column(sa.Column("honeypot_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("retired", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("created_at", TIME, nullable=False, server_default=epoch))
        batch.create_foreign_key("fk_agents_honeypot_id", "honeypots", ["honeypot_id"], ["id"])
        batch.create_index("ix_agents_honeypot_id", ["honeypot_id"])

    with op.batch_alter_table("deployments") as batch:
        batch.alter_column("initiated_by", existing_type=sa.String(), nullable=True)
        batch.add_column(sa.Column("operation", sa.String(), nullable=False, server_default="deploy"))
        batch.add_column(sa.Column("runtime_identifier", sa.String(), nullable=True))

    op.create_table(
        "network_endpoints",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("host_id", sa.String(), nullable=False),
        sa.Column("network", sa.String(), nullable=False),
        sa.Column("protocol", sa.String(), nullable=False),
        sa.Column("alias", sa.String(), nullable=False),
        sa.Column("internal_port", sa.Integer(), nullable=False),
        sa.Column("published_port", sa.Integer(), nullable=True),
        sa.Column("allocation_status", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("honeypot_id", sa.String(), nullable=False),
        sa.Column("created_at", TIME, nullable=False),
        sa.ForeignKeyConstraint(["honeypot_id"], ["honeypots.id"]),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("honeypot_id"),
        sa.UniqueConstraint("host_id", "network", "alias", name="uq_endpoint_host_network_alias"),
        sa.UniqueConstraint("host_id", "network", "internal_port", name="uq_endpoint_host_network_port"))
    op.create_table(
        "deployment_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("honeypot_id", sa.String(), nullable=False),
        sa.Column("deployment_id", sa.String(), nullable=True),
        sa.Column("timestamp", TIME, nullable=False),
        sa.Column("level", sa.String(), nullable=False),
        sa.Column("code", sa.String(), nullable=False),
        sa.Column("details", JSON, nullable=False),
        sa.ForeignKeyConstraint(["deployment_id"], ["deployments.id"]),
        sa.ForeignKeyConstraint(["honeypot_id"], ["honeypots.id"]),
        sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_deployment_logs_honeypot_id", "deployment_logs", ["honeypot_id"])
    op.create_index("ix_deployment_logs_deployment_id", "deployment_logs", ["deployment_id"])

    migrate_slots(bind)


def migrate_slots(bind):
    """Turn slot-bound honeypots into dynamic instances without touching their history."""
    moment = datetime.now(timezone.utc)
    bind.execute(sa.text("UPDATE honeypots SET updated_at = created_at"))
    bind.execute(sa.text("UPDATE agents SET created_at = :at"), {"at": moment})
    pots = bind.execute(sa.text(
        "SELECT h.id, h.desired_state, h.generation, p.spec, p.version FROM honeypots h "
        "JOIN honeypot_profiles p ON p.id = h.profile_id ORDER BY h.created_at")).all()
    if not bind.execute(sa.text("SELECT 1 FROM hosts WHERE id = :id"), {"id": LAB_HOST}).first():
        bind.execute(sa.text(
            "INSERT INTO hosts (id, name, management_address, approved, provisioning, created_at) "
            "VALUES (:id, :name, 'controller', :approved, 'controller', :at)"),
            {"id": LAB_HOST, "name": "Локальный узел лаборатории", "approved": True, "at": moment})
    used = set()
    for identifier, desired, generation, spec, version in pots:
        spec = json.loads(spec) if isinstance(spec, str) else dict(spec)
        port = spec.get("port", 8022)
        if not 8000 <= port <= 8999:
            port = 8000
        while port in used:
            port += 1
        used.add(port)
        configuration = spec | {"port": port}
        bind.execute(sa.text(
            "UPDATE honeypots SET host_id = :host, configuration = :configuration, profile_version = :version, "
            "generation = :generation, status = :status, transition_at = :at, error = NULL, last_seen = NULL, "
            "ip_address = NULL WHERE id = :id").bindparams(sa.bindparam("configuration", type_=JSON)),
            {"host": LAB_HOST, "configuration": configuration, "version": version, "generation": generation + 1,
             "status": "deploying" if desired == "running" else "stopping", "at": moment, "id": identifier})
        bind.execute(sa.text(
            "INSERT INTO network_endpoints (id, host_id, network, protocol, alias, internal_port, allocation_status, "
            "mode, honeypot_id, created_at) VALUES (:id, :host, 'decoy', 'tcp', :alias, :port, 'reserved', 'auto', :pot, :at)"),
            {"id": str(uuid.uuid4()), "host": LAB_HOST, "alias": "hp-" + identifier[:8], "port": port,
             "pot": identifier, "at": moment})
    bind.execute(sa.text(
        "UPDATE agents SET retired = :yes, approved = :no, honeypot_id = "
        "(SELECT h.id FROM honeypots h WHERE h.host_id = :host AND EXISTS "
        "(SELECT 1 FROM telemetry_events e WHERE e.agent_id = agents.id AND e.honeypot_id = h.id) LIMIT 1), host_id = NULL"),
        {"yes": True, "no": False, "host": LAB_HOST})
    bind.execute(sa.text("UPDATE deployments SET host_id = :host"), {"host": LAB_HOST})
    bind.execute(sa.text("UPDATE management_commands SET status = 'superseded' WHERE status = 'pending'"))
    bind.execute(sa.text("UPDATE deployments SET status = 'cancelled' WHERE status = 'pending'"))
    bind.execute(sa.text("DELETE FROM hosts WHERE id <> :host"), {"host": LAB_HOST})


def downgrade():
    raise RuntimeError("Возврат к модели двух слотов не поддерживается: восстановите резервную копию базы данных")
