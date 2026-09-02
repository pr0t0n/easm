"""Archive excess crawler pending review backlog.

Revision ID: 0036
Revises: 0035
"""
from alembic import op


revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        WITH ranked AS (
            SELECT id,
                   row_number() OVER (
                       ORDER BY created_at DESC NULLS LAST, id DESC
                   ) AS rn
            FROM vulnerability_learnings
            WHERE source_kind = 'github_hackerone_crawler'
              AND status = 'pending_review'
        )
        UPDATE vulnerability_learnings AS learning
        SET status = 'archived',
            review_notes = concat_ws(
                E'\\n',
                NULLIF(review_notes, ''),
                'Auto-archived by migration 0036: crawler pending-review backlog exceeded retention cap.'
            ),
            updated_at = now()
        FROM ranked
        WHERE learning.id = ranked.id
          AND ranked.rn > 10000
        """
    )


def downgrade() -> None:
    pass
