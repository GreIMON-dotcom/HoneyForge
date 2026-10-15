"""Persist the actual profile version acknowledged by the isolated service."""
from alembic import op
import sqlalchemy as sa

revision = "8b141750e962"
down_revision = "947762118ddc"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("honeypots", sa.Column("applied_profile_version", sa.Integer(), nullable=False, server_default="0"))


def downgrade():
    op.drop_column("honeypots", "applied_profile_version")
