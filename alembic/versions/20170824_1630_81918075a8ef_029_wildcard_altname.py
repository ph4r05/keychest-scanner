"""029 wildcard altname

Revision ID: 81918075a8ef
Revises: 91838d3c577d
Create Date: 2017-08-24 16:30:15.105854+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '81918075a8ef'
down_revision = '91838d3c577d'
branch_labels = None
depends_on = None


def upgrade():
    """
    Upgrade
    :return:
    """
    op.add_column('certificate_alt_names',
                  sa.Column('is_wildcard', sa.SmallInteger(), nullable=False, server_default='0'))

    op.drop_constraint('PRIMARY', 'certificate_alt_names', type_='primary')
    op.create_primary_key("pk_certificate_alt_names", "certificate_alt_names", ['cert_id', 'alt_name', 'is_wildcard'])


def downgrade():
    """
    Downgrade
    :return:
    """
    op.drop_constraint('PRIMARY', 'certificate_alt_names', type_='primary')
    op.drop_column('certificate_alt_names', 'is_wildcard')
    op.create_primary_key("pk_certificate_alt_names", "certificate_alt_names", ['cert_id', 'alt_name'])
