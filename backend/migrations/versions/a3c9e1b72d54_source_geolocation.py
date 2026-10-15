"""Cache of source address classification and optional local geolocation."""
from alembic import op
import sqlalchemy as sa

revision = "a3c9e1b72d54"
down_revision = "e7a4d2c91f30"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "source_geo",
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("scope", sa.String(length=10), nullable=False),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("country_name", sa.String(), nullable=True),
        sa.Column("city", sa.String(), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("asn", sa.String(), nullable=True),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("ip_address"))
    op.create_index("ix_source_geo_country_code", "source_geo", ["country_code"])


def downgrade():
    op.drop_index("ix_source_geo_country_code", table_name="source_geo")
    op.drop_table("source_geo")
