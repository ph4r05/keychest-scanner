"""057 managed entities

Revision ID: 80cfdf4ce911
Revises: 357b8192ce0f
Create Date: 2018-01-17 09:55:47.688115+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '80cfdf4ce911'
down_revision = '357b8192ce0f'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('managed_cert_chains',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('certificate_id', sa.BigInteger(), nullable=False),
                    sa.Column('chain_certificate_id', sa.BigInteger(), nullable=False),
                    sa.Column('order_num', sa.SmallInteger(), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'],
                                            name='fk_managed_cert_chains_certificate_id', ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['chain_certificate_id'], ['certificates.id'],
                                            name='fk_managed_cert_chains_chain_certificate_id', ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('certificate_id', 'chain_certificate_id', 'order_num',
                                        name='uk_managed_cert_chains_cert_order_rel'),
                    sa.UniqueConstraint('certificate_id', 'chain_certificate_id',
                                        name='uk_managed_cert_chains_cert_rel')
                    )
    op.create_index(op.f('ix_managed_cert_chains_certificate_id'), 'managed_cert_chains', ['certificate_id'],
                    unique=False)
    op.create_index(op.f('ix_managed_cert_chains_chain_certificate_id'), 'managed_cert_chains',
                    ['chain_certificate_id'], unique=False)

    op.create_table('managed_cert_privates',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('certificate_id', sa.BigInteger(), nullable=False),
                    sa.Column('private_data', sa.Text(), nullable=True),
                    sa.Column('private_hash', sa.String(length=64), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'],
                                            name='fk_managed_cert_privates_certificate_id', ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.create_index(op.f('ix_managed_cert_privates_certificate_id'), 'managed_cert_privates', ['certificate_id'],
                    unique=False)
    op.create_index(op.f('ix_managed_cert_privates_private_hash'), 'managed_cert_privates', ['private_hash'],
                    unique=False)


def downgrade():
    op.drop_table('managed_cert_privates')
    op.drop_table('managed_cert_chains')

