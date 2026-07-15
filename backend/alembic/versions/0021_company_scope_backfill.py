"""company scope backfill

Revision ID: 0021
Revises: 0020
"""
from alembic import op


revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        WITH owner_user AS (
            SELECT id
            FROM users
            ORDER BY is_admin DESC, id ASC
            LIMIT 1
        )
        INSERT INTO access_groups (owner_id, name, description, created_at)
        SELECT id, 'Default Company', 'Backfill para escopo multiempresa', NOW()
        FROM owner_user
        WHERE NOT EXISTS (
            SELECT 1 FROM access_groups WHERE name = 'Default Company'
        )
        """
    )
    op.execute(
        """
        WITH default_group AS (
            SELECT id FROM access_groups WHERE name = 'Default Company' LIMIT 1
        )
        INSERT INTO user_access_groups (user_id, group_id)
        SELECT u.id, dg.id
        FROM users u
        CROSS JOIN default_group dg
        WHERE NOT EXISTS (
            SELECT 1 FROM user_access_groups uag WHERE uag.user_id = u.id
        )
        ON CONFLICT DO NOTHING
        """
    )
    op.execute(
        """
        WITH first_group AS (
            SELECT DISTINCT ON (user_id) user_id, group_id
            FROM user_access_groups
            ORDER BY user_id, group_id
        )
        UPDATE scan_jobs sj
        SET access_group_id = fg.group_id
        FROM first_group fg
        WHERE sj.access_group_id IS NULL
          AND sj.owner_id = fg.user_id
        """
    )
    op.execute(
        """
        WITH first_group AS (
            SELECT DISTINCT ON (user_id) user_id, group_id
            FROM user_access_groups
            ORDER BY user_id, group_id
        )
        UPDATE scheduled_scans ss
        SET access_group_id = fg.group_id
        FROM first_group fg
        WHERE ss.access_group_id IS NULL
          AND ss.owner_id = fg.user_id
        """
    )


def downgrade() -> None:
    # Backfill is intentionally non-destructive.
    pass
