"""036 cert trush path fields

Revision ID: 8fedecff0ae9
Revises: 9780d115b745
Create Date: 2017-09-13 22:53:35.679969+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8fedecff0ae9'
down_revision = '9780d115b745'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('certificates', sa.Column('authority_key_info', sa.String(length=64), nullable=True))
    op.add_column('certificates', sa.Column('root_parent_id', sa.BigInteger(), nullable=True))
    op.add_column('certificates', sa.Column('subject_key_info', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_certificates_authority_key_info'), 'certificates', ['authority_key_info'], unique=False)
    op.create_index(op.f('ix_certificates_subject_key_info'), 'certificates', ['subject_key_info'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_certificates_subject_key_info'), table_name='certificates')
    op.drop_index(op.f('ix_certificates_authority_key_info'), table_name='certificates')
    op.drop_column('certificates', 'subject_key_info')
    op.drop_column('certificates', 'root_parent_id')
    op.drop_column('certificates', 'authority_key_info')
    # ### end Alembic commands ###
