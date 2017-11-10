"""043 unique key clashes

Revision ID: 7d81e713a73e
Revises: b635323148a1
Create Date: 2017-11-10 16:26:54.836819+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7d81e713a73e'
down_revision = 'b635323148a1'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint('domain_name', 'domain_name', type_='unique')
    op.drop_constraint('domain_name', 'base_domain', type_='unique')
    op.drop_constraint('event_key', 'system_last_events', type_='unique')
    op.drop_constraint('service_name', 'watch_service', type_='unique')
    op.drop_constraint('ip_addr', 'ip_address', type_='unique')

    op.create_unique_constraint('uk_domain_name_domain_name', 'domain_name', ['domain_name'])
    op.create_unique_constraint('uk_base_domain_domain_name', 'base_domain', ['domain_name'])
    op.create_unique_constraint('uk_system_last_events_event_key', 'system_last_events', ['event_key'])
    op.create_unique_constraint('uk_watch_service_service_name', 'watch_service', ['service_name'])
    op.create_unique_constraint('uk_ip_address_ip_addr', 'ip_address', ['ip_addr'])


def downgrade():
    op.drop_constraint('uk_domain_name_domain_name', 'domain_name', type_='unique')
    op.drop_constraint('uk_base_domain_domain_name', 'base_domain', type_='unique')
    op.drop_constraint('uk_system_last_events_event_key', 'system_last_events', type_='unique')
    op.drop_constraint('uk_watch_service_service_name', 'watch_service', type_='unique')
    op.drop_constraint('uk_ip_address_ip_addr', 'ip_address', type_='unique')

    op.create_unique_constraint('domain_name', 'domain_name', ['domain_name'])
    op.create_unique_constraint('domain_name', 'base_domain', ['domain_name'])
    op.create_unique_constraint('event_key', 'system_last_events', ['event_key'])
    op.create_unique_constraint('service_name', 'watch_service', ['service_name'])
    op.create_unique_constraint('ip_addr', 'ip_address', ['ip_addr'])

