"""Record the decoy supervisor's observed laboratory address."""
from alembic import op
import sqlalchemy as sa

revision = 'c51aa2fc901d'
down_revision = 'b93e1a4c0217'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('honeypots', sa.Column('ip_address', sa.String(length=45), nullable=True))


def downgrade():
    op.drop_column('honeypots', 'ip_address')
