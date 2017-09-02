"""001 new scan system

Revision ID: 9a246a12d5e3
Revises: 
Create Date: 2017-06-29 20:55:33.109493

"""
from alembic import op
from alembic import context

import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy.dialects.mysql import INTEGER
from sqlalchemy import event, UniqueConstraint
from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger, SmallInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session as BaseSession, relationship

import logging

# revision identifiers, used by Alembic.
revision = '9a246a120000'
down_revision = None
branch_labels = None
depends_on = None


#
# Migration methods
#


def upgrade():
    """
    Upgrade
    :return:
    """
    op.create_table('certificates',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('crt_sh_id', sa.BigInteger(), nullable=True),
                    sa.Column('crt_sh_ca_id', sa.BigInteger(), nullable=True),
                    sa.Column('fprint_sha1', sa.String(length=40), nullable=False),
                    sa.Column('fprint_sha256', sa.String(length=64), nullable=True),
                    sa.Column('valid_from', sa.DateTime(), nullable=True),
                    sa.Column('valid_to', sa.DateTime(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('cname', sa.Text(), nullable=True),
                    sa.Column('subject', sa.Text(), nullable=True),
                    sa.Column('issuer', sa.Text(), nullable=True),
                    sa.Column('is_ca', sa.SmallInteger(), nullable=False),
                    sa.Column('is_self_signed', sa.SmallInteger(), nullable=False),
                    sa.Column('is_precert', sa.SmallInteger(), nullable=False),
                    sa.Column('is_precert_ca', sa.SmallInteger(), nullable=False),
                    sa.Column('parent_id', sa.BigInteger(), nullable=True),
                    sa.Column('is_le', sa.SmallInteger(), nullable=False),
                    sa.Column('is_cloudflare', sa.SmallInteger(), nullable=False),
                    sa.Column('alt_names', sa.Text(), nullable=True),
                    sa.Column('source', sa.String(length=255), nullable=True),
                    sa.Column('pem', sa.Text(), nullable=True),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.create_index(op.f('ix_certificates_crt_sh_id'), 'certificates', ['crt_sh_id'], unique=False)
    op.create_index(op.f('ix_certificates_fprint_sha1'), 'certificates', ['fprint_sha1'], unique=False)
    op.create_index(op.f('ix_certificates_fprint_sha256'), 'certificates', ['fprint_sha256'], unique=False)

    op.create_table('certificate_alt_names',
                    sa.Column('cert_id', sa.BigInteger(), nullable=False),
                    sa.Column('alt_name', sa.String(length=255), nullable=False),
                    sa.PrimaryKeyConstraint('cert_id', 'alt_name')
                    )
    op.create_index(op.f('ix_certificate_alt_names_alt_name'), 'certificate_alt_names', ['alt_name'], unique=False)
    op.create_index(op.f('ix_certificate_alt_names_cert_id'), 'certificate_alt_names', ['cert_id'], unique=False)

    op.create_table('crtsh_query',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('job_id', sa.BigInteger(), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('status', sa.SmallInteger(), nullable=True),
                    sa.Column('results', sa.Integer(), nullable=True),
                    sa.Column('new_results', sa.Integer(), nullable=True),
                    sa.Column('certs_ids', sa.Text(), nullable=True),
                    sa.PrimaryKeyConstraint('id')
                    )

    op.create_table('crtsh_query_results',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('query_id', sa.BigInteger(), nullable=True),
                    sa.Column('job_id', sa.BigInteger(), nullable=True),
                    sa.Column('crt_id', sa.BigInteger(), nullable=True),
                    sa.Column('crt_sh_id', sa.BigInteger(), nullable=True),
                    sa.Column('was_new', sa.SmallInteger(), nullable=True),
                    sa.PrimaryKeyConstraint('id')
                    )

    op.create_table('scan_handshakes',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('job_id', sa.BigInteger(), nullable=True),
                    sa.Column('ip_scanned', sa.String(length=255), nullable=True),
                    sa.Column('tls_ver', sa.String(length=16), nullable=True),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('status', sa.SmallInteger(), nullable=True),
                    sa.Column('err_code', sa.SmallInteger(), nullable=True),
                    sa.Column('time_elapsed', sa.Integer(), nullable=True),
                    sa.Column('results', sa.Integer(), nullable=True),
                    sa.Column('new_results', sa.Integer(), nullable=True),
                    sa.Column('certs_ids', sa.Text(), nullable=True),
                    sa.Column('cert_id_leaf', sa.BigInteger(), nullable=True),
                    sa.Column('valid_path', sa.SmallInteger(), nullable=True),
                    sa.Column('valid_hostname', sa.SmallInteger(), nullable=True),
                    sa.Column('err_validity', sa.String(length=64), nullable=True),
                    sa.Column('err_many_leafs', sa.SmallInteger(), nullable=True),
                    sa.Column('req_https_result', sa.String(length=64), nullable=True),
                    sa.Column('follow_http_result', sa.String(length=64), nullable=True),
                    sa.Column('follow_https_result', sa.String(length=64), nullable=True),
                    sa.Column('follow_http_url', sa.String(length=255), nullable=True),
                    sa.Column('follow_https_url', sa.String(length=255), nullable=True),
                    sa.Column('hsts_present', sa.SmallInteger(), nullable=True),
                    sa.Column('hsts_max_age', sa.BigInteger(), nullable=True),
                    sa.Column('hsts_include_subdomains', sa.SmallInteger(), nullable=True),
                    sa.Column('hsts_preload', sa.SmallInteger(), nullable=True),
                    sa.Column('pinning_present', sa.SmallInteger(), nullable=True),
                    sa.Column('pinning_report_only', sa.SmallInteger(), nullable=True),
                    sa.Column('pinning_pins', sa.Text(), nullable=True),
                    sa.PrimaryKeyConstraint('id')
                    )

    op.create_table('scan_handshake_results',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('scan_id', sa.BigInteger(), nullable=True),
                    sa.Column('job_id', sa.BigInteger(), nullable=True),
                    sa.Column('crt_id', sa.BigInteger(), nullable=True),
                    sa.Column('crt_sh_id', sa.BigInteger(), nullable=True),
                    sa.Column('was_new', sa.SmallInteger(), nullable=True),
                    sa.Column('is_ca', sa.SmallInteger(), nullable=True),
                    sa.PrimaryKeyConstraint('id')
                    )

    op.create_table('watch_target',
                    sa.Column('id', sa.BigInteger(), nullable=False),
                    sa.Column('scan_host', sa.String(length=255), nullable=False),
                    sa.Column('scan_scheme', sa.String(length=255), nullable=True),
                    sa.Column('scan_port', sa.String(length=255), nullable=True),
                    sa.Column('scan_connect', sa.SmallInteger(), nullable=False),
                    sa.Column('created_at', sa.DateTime(), nullable=True),
                    sa.Column('updated_at', sa.DateTime(), nullable=True),
                    sa.Column('last_scan_at', sa.DateTime(), nullable=True),
                    sa.Column('user_id', sa.BigInteger(), nullable=True),
                    sa.Column('scan_periodicity', sa.BigInteger(), nullable=True),
                    sa.PrimaryKeyConstraint('id')
                    )


def downgrade():
    """
    Downgrade
    :return:
    """
    op.drop_table('watch_target')
    op.drop_table('scan_handshake_results')
    op.drop_table('scan_handshakes')
    op.drop_table('crtsh_query_results')
    op.drop_table('crtsh_query')

    op.drop_index(op.f('ix_certificates_crt_sh_id'), table_name='certificates')
    op.drop_index(op.f('ix_certificates_fprint_sha1'), table_name='certificates')
    op.drop_index(op.f('ix_certificates_fprint_sha256'), table_name='certificates')
    op.drop_index(op.f('ix_certificate_alt_names_alt_name'), table_name='certificate_alt_names')
    op.drop_index(op.f('ix_certificate_alt_names_cert_id'), table_name='certificate_alt_names')

    op.drop_table('certificate_alt_names')
    op.drop_table('certificates')


