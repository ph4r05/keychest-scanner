-- Alembic has troubles with DEFAULT values - sometimes needed to be added manually
-- Especially to tables used by Laravel also.

ALTER TABLE users MODIFY COLUMN utc_offset int(11) NOT NULL DEFAULT 0;
ALTER TABLE users MODIFY COLUMN is_superadmin smallint(6) NOT NULL DEFAULT 0;
ALTER TABLE users MODIFY COLUMN weekly_emails_disabled smallint(6) NOT NULL DEFAULT 0;
