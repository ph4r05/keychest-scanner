"""028 watch target extended for ip scan

Revision ID: 91838d3c577d
Revises: 32cbbd5953d8
Create Date: 2017-08-24 14:29:43.545438+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '91838d3c577d'
down_revision = '32cbbd5953d8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('watch_target', sa.Column('ip_scan_id', sa.BigInteger(), nullable=True))
    op.add_column('watch_target', sa.Column('manual_dns', sa.SmallInteger(), nullable=False, server_default='0'))
    op.alter_column('watch_target', 'is_ip_host',
               existing_type=mysql.SMALLINT(display_width=6),
               nullable=False, server_default='0')
    op.alter_column('watch_target', 'last_scan_state',
               existing_type=mysql.SMALLINT(display_width=6),
               nullable=False, server_default='0')
    op.alter_column('watch_target', 'scan_connect',
               existing_type=mysql.SMALLINT(display_width=6),
               nullable=False, server_default='0')
    op.create_index(op.f('ix_watch_target_ip_scan_id'), 'watch_target', ['ip_scan_id'], unique=False)
    op.create_foreign_key('wt_ip_scan_record_id', 'watch_target', 'ip_scan_record', ['ip_scan_id'], ['id'], ondelete='SET NULL')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('wt_ip_scan_record_id', 'watch_target', type_='foreignkey')
    op.drop_index(op.f('ix_watch_target_ip_scan_id'), table_name='watch_target')
    op.alter_column('watch_target', 'scan_connect',
               existing_type=mysql.SMALLINT(display_width=6),
               nullable=True)
    op.alter_column('watch_target', 'last_scan_state',
               existing_type=mysql.SMALLINT(display_width=6),
               nullable=True)
    op.alter_column('watch_target', 'is_ip_host',
               existing_type=mysql.SMALLINT(display_width=6),
               nullable=True)
    op.drop_column('watch_target', 'manual_dns')
    op.drop_column('watch_target', 'ip_scan_id')
    # ### end Alembic commands ###
