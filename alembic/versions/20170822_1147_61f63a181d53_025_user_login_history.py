"""025 user login history

Revision ID: 61f63a181d53
Revises: 5d917d7d2e61
Create Date: 2017-08-22 11:47:02.282728+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '61f63a181d53'
down_revision = '5d917d7d2e61'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user_login_history',
    sa.Column('id', mysql.INTEGER(display_width=10, unsigned=True), nullable=False),
    sa.Column('user_id', mysql.INTEGER(display_width=10, unsigned=True), nullable=False),
    sa.Column('login_at', sa.DateTime(), nullable=True),
    sa.Column('login_ip', sa.String(length=191), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='user_login_history_users_id', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_login_history_user_id'), 'user_login_history', ['user_id'], unique=False)
    op.add_column('users', sa.Column('last_login_id', mysql.INTEGER(display_width=10, unsigned=True), nullable=True))
    op.create_index(op.f('ix_users_last_login_id'), 'users', ['last_login_id'], unique=False)
    op.create_foreign_key('users_user_login_history_id', 'users', 'user_login_history', ['last_login_id'], ['id'], ondelete='SET NULL')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('users_user_login_history_id', 'users', type_='foreignkey')
    op.drop_constraint('user_login_history_users_id', 'user_login_history', type_='foreignkey')
    op.drop_index(op.f('ix_users_last_login_id'), table_name='users')
    op.drop_column('users', 'last_login_id')
    op.drop_index(op.f('ix_user_login_history_user_id'), table_name='user_login_history')
    op.drop_table('user_login_history')
    # ### end Alembic commands ###