"""041 mgmt keys

Revision ID: b2d5a62db9cf
Revises: 5db281725401
Create Date: 2017-10-25 12:18:13.855633+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b2d5a62db9cf'
down_revision = '5db281725401'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ssh_keys',
    sa.Column('id', sa.BigInteger(), nullable=False),
    sa.Column('key_id', sa.String(length=64), nullable=True),
    sa.Column('pub_key', sa.Text(), nullable=True),
    sa.Column('priv_key', sa.Text(), nullable=True),
    sa.Column('key_type', sa.SmallInteger(), nullable=True),
    sa.Column('storage_type', sa.SmallInteger(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('key_id', name='ssh_keys_key_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('ssh_keys')
    # ### end Alembic commands ###
