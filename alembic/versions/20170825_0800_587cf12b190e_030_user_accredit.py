"""030 user accredit

Revision ID: 587cf12b190e
Revises: 81918075a8ef
Create Date: 2017-08-25 08:00:45.007091+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '587cf12b190e'
down_revision = '81918075a8ef'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('accredit', sa.String(length=100), nullable=True))


def downgrade():
    op.drop_column('users', 'accredit')


