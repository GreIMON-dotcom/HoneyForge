"""Distinguish pre-provisioned and locally orchestrated laboratory targets."""
from alembic import op
import sqlalchemy as sa

revision = "b93e1a4c0217"
down_revision = "8b141750e962"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("hosts", sa.Column("provisioning", sa.String(), nullable=False, server_default="compose"))


def downgrade():
    op.drop_column("hosts", "provisioning")
