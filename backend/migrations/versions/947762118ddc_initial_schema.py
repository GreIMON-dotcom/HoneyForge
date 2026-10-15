"""initial_schema"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql
revision = '947762118ddc'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('audit_logs',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('actor', sa.String(), nullable=False),
    sa.Column('action', sa.String(), nullable=False),
    sa.Column('resource', sa.String(), nullable=False),
    sa.Column('result', sa.String(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'], unique=False)
    op.create_table('honeypot_profiles',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('spec', sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('hosts',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('management_address', sa.String(), nullable=False),
    sa.Column('approved', sa.Boolean(), nullable=False),
    sa.Column('service_type', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('password_hash', sa.String(), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('agents',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('host_id', sa.String(), nullable=False),
    sa.Column('token_hash', sa.String(), nullable=False),
    sa.Column('approved', sa.Boolean(), nullable=False),
    sa.Column('version', sa.String(), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('host_id')
    )
    op.create_table('honeypots',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('profile_id', sa.String(), nullable=False),
    sa.Column('host_id', sa.String(), nullable=False),
    sa.Column('desired_state', sa.String(), nullable=False),
    sa.Column('generation', sa.Integer(), nullable=False),
    sa.Column('applied_generation', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
    sa.Column('queue_size', sa.Integer(), nullable=False),
    sa.Column('error', sa.String(), nullable=True),
    sa.Column('last_delivery', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
    sa.ForeignKeyConstraint(['profile_id'], ['honeypot_profiles.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('host_id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('login_sessions',
    sa.Column('token_hash', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('token_hash')
    )
    op.create_index(op.f('ix_login_sessions_expires_at'), 'login_sessions', ['expires_at'], unique=False)
    op.create_table('alert_rules',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('honeypot_id', sa.String(), nullable=True),
    sa.Column('event_type', sa.String(), nullable=False),
    sa.Column('threshold', sa.Integer(), nullable=False),
    sa.Column('window_seconds', sa.Integer(), nullable=False),
    sa.Column('severity', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['honeypot_id'], ['honeypots.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('deployments',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('honeypot_id', sa.String(), nullable=False),
    sa.Column('host_id', sa.String(), nullable=False),
    sa.Column('profile_id', sa.String(), nullable=False),
    sa.Column('initiated_by', sa.String(), nullable=False),
    sa.Column('generation', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('error_message', sa.String(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['honeypot_id'], ['honeypots.id'], ),
    sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
    sa.ForeignKeyConstraint(['initiated_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['profile_id'], ['honeypot_profiles.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('management_commands',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('honeypot_id', sa.String(), nullable=False),
    sa.Column('command_type', sa.String(), nullable=False),
    sa.Column('generation', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('error', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['honeypot_id'], ['honeypots.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('sessions',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('honeypot_id', sa.String(), nullable=False),
    sa.Column('session_uid', sa.String(), nullable=False),
    sa.Column('source_ip', sa.String(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ended_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('event_count', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['honeypot_id'], ['honeypots.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('honeypot_id', 'session_uid')
    )
    op.create_table('telemetry_events',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('event_uid', sa.String(), nullable=False),
    sa.Column('honeypot_id', sa.String(), nullable=False),
    sa.Column('agent_id', sa.String(), nullable=False),
    sa.Column('session_id', sa.String(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('source_ip', sa.String(length=45), nullable=False),
    sa.Column('source_port', sa.Integer(), nullable=False),
    sa.Column('destination_port', sa.Integer(), nullable=False),
    sa.Column('protocol', sa.String(length=10), nullable=False),
    sa.Column('event_type', sa.String(length=40), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('payload', sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
    sa.ForeignKeyConstraint(['honeypot_id'], ['honeypots.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('agent_id', 'event_uid')
    )
    op.create_index('ix_events_hp_type_received', 'telemetry_events', ['honeypot_id', 'event_type', 'received_at'], unique=False)
    op.create_index(op.f('ix_telemetry_events_event_type'), 'telemetry_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_telemetry_events_honeypot_id'), 'telemetry_events', ['honeypot_id'], unique=False)
    op.create_index(op.f('ix_telemetry_events_protocol'), 'telemetry_events', ['protocol'], unique=False)
    op.create_index(op.f('ix_telemetry_events_received_at'), 'telemetry_events', ['received_at'], unique=False)
    op.create_index(op.f('ix_telemetry_events_severity'), 'telemetry_events', ['severity'], unique=False)
    op.create_index(op.f('ix_telemetry_events_source_ip'), 'telemetry_events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_telemetry_events_timestamp'), 'telemetry_events', ['timestamp'], unique=False)
    op.create_table('alerts',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('rule_id', sa.String(), nullable=False),
    sa.Column('honeypot_id', sa.String(), nullable=False),
    sa.Column('severity', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('triggered_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'), nullable=False),
    sa.ForeignKeyConstraint(['honeypot_id'], ['honeypots.id'], ),
    sa.ForeignKeyConstraint(['rule_id'], ['alert_rules.id'], ),
    sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    op.drop_table('alerts')
    op.drop_index(op.f('ix_telemetry_events_timestamp'), table_name='telemetry_events')
    op.drop_index(op.f('ix_telemetry_events_source_ip'), table_name='telemetry_events')
    op.drop_index(op.f('ix_telemetry_events_severity'), table_name='telemetry_events')
    op.drop_index(op.f('ix_telemetry_events_received_at'), table_name='telemetry_events')
    op.drop_index(op.f('ix_telemetry_events_protocol'), table_name='telemetry_events')
    op.drop_index(op.f('ix_telemetry_events_honeypot_id'), table_name='telemetry_events')
    op.drop_index(op.f('ix_telemetry_events_event_type'), table_name='telemetry_events')
    op.drop_index('ix_events_hp_type_received', table_name='telemetry_events')
    op.drop_table('telemetry_events')
    op.drop_table('sessions')
    op.drop_table('management_commands')
    op.drop_table('deployments')
    op.drop_table('alert_rules')
    op.drop_index(op.f('ix_login_sessions_expires_at'), table_name='login_sessions')
    op.drop_table('login_sessions')
    op.drop_table('honeypots')
    op.drop_table('agents')
    op.drop_table('users')
    op.drop_table('hosts')
    op.drop_table('honeypot_profiles')
    op.drop_index(op.f('ix_audit_logs_timestamp'), table_name='audit_logs')
    op.drop_table('audit_logs')
