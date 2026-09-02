"""Quarantine unsynthesized crawler learnings.

Revision ID: 0035
Revises: 0034
"""
from alembic import op


revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM vulnerability_learnings accepted
        WHERE accepted.source_kind = 'github_hackerone_crawler'
          AND accepted.status = 'accepted'
          AND (accepted.raw_llm_response IS NULL OR trim(accepted.raw_llm_response) = '')
          AND EXISTS (
              SELECT 1
              FROM vulnerability_learnings pending
              WHERE pending.source_kind = accepted.source_kind
                AND pending.status = 'pending_review'
                AND pending.title = accepted.title
          )
        """
    )
    op.execute(
        """
        UPDATE vulnerability_learnings
        SET status = 'pending_review',
            accepted_by_id = NULL,
            accepted_at = NULL,
            review_notes = concat_ws(
                E'\\n',
                NULLIF(review_notes, ''),
                'Auto-quarantined by migration 0035: crawler learning had accepted status without LLM synthesis.'
            ),
            updated_at = now()
        WHERE source_kind = 'github_hackerone_crawler'
          AND status = 'accepted'
          AND (raw_llm_response IS NULL OR trim(raw_llm_response) = '')
        """
    )


def downgrade() -> None:
    pass
