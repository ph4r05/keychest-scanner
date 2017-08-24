"""029 wildcard altname

Revision ID: d82dd77a17dc
Revises: 91838d3c577d
Create Date: 2017-08-24 16:21:24.720662+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd82dd77a17dc'
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


def downgrade():
    """
    Downgrade
    :return:
    """
    op.drop_column('certificate_alt_names', 'is_wildcard')
