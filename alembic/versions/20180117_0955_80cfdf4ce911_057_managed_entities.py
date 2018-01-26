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

    op.create_table('managed_security_groups',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('sgrp_name', sa.String(length=255), nullable=True),
                    sa.Column('sgrp_desc', sa.Text(), nullable=True),
                    sa.Column('sgrp_data', sa.Text(), nullable=True),
                    sa.Column('sgrp_type', sa.String(length=64), nullable=True),
                    sa.Column('sgrp_assurance_level', sa.String(length=64), nullable=True),
                    sa.Column('sgrp_criticality', sa.Integer(), nullable=True),
                    sa.Column('owner_id', sa.BigInteger(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('deleted_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['owner_id'], ['owners.id'], name='managed_security_groups_owner_id',
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('sgrp_name', 'owner_id', name='uk_managed_security_groups_name_owner')
                    )
    op.create_index(op.f('ix_managed_security_groups_owner_id'), 'managed_security_groups', ['owner_id'], unique=False)

    op.create_table('managed_service_to_security_group',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('service_id', sa.BigInteger(), nullable=False),
                    sa.Column('group_id', sa.BigInteger(), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('deleted_at', sa.DateTime(), nullable=True),
                    sa.ForeignKeyConstraint(['group_id'], ['managed_host_groups.id'],
                                            name='managed_service_to_security_group_group_id', ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['service_id'], ['managed_services.id'],
                                            name='managed_service_to_security_group_service_id', ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('service_id', 'group_id', name='uk_managed_service_to_security_group_svc_group')
                    )
    op.create_index(op.f('ix_managed_service_to_security_group_group_id'), 'managed_service_to_security_group',
                    ['group_id'], unique=False)
    op.create_index(op.f('ix_managed_service_to_security_group_service_id'), 'managed_service_to_security_group',
                    ['service_id'], unique=False)

    op.add_column('managed_certificates', sa.Column('check_trigger', sa.DateTime(), nullable=True))
    op.add_column('managed_hosts', sa.Column('ansible_check_trigger', sa.DateTime(), nullable=True))
    op.add_column('managed_services', sa.Column('config_check_trigger', sa.DateTime(), nullable=True))
    op.add_column('managed_services', sa.Column('config_last_data', sa.Text(), nullable=True))
    op.add_column('managed_services', sa.Column('config_last_check', sa.DateTime(), nullable=True))
    op.add_column('managed_services', sa.Column('config_last_status', sa.SmallInteger(), nullable=False))
    op.add_column('managed_tests', sa.Column('check_trigger', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_table('managed_cert_privates')
    op.drop_table('managed_cert_chains')
    op.drop_table('managed_service_to_security_group')
    op.drop_table('managed_security_groups')

    op.drop_column('managed_tests', 'check_trigger')
    op.drop_column('managed_services', 'config_last_status')
    op.drop_column('managed_services', 'config_last_check')
    op.drop_column('managed_services', 'config_last_data')
    op.drop_column('managed_services', 'config_check_trigger')
    op.drop_column('managed_hosts', 'ansible_check_trigger')
    op.drop_column('managed_certificates', 'check_trigger')



