"""findings: add verification_status, url columns

Revision ID: 0014
Revises: 0013_scan_work_items
Create Date: 2026-05-27

verification_status: confirmed | candidate | hypothesis
  - confirmed  : tool prova a condição diretamente (sqlmap, dalfox, nuclei com matcher)
  - candidate  : precisa de verificação secundária (FP possível)
  - hypothesis : correlação passiva de versão — não testou a condição

url: endpoint específico onde o finding foi encontrado (para business impact scoring)
"""

from alembic import op
import sqlalchemy as sa

revision = '0014'
down_revision = '0013_scan_work_items'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'findings',
        sa.Column(
            'verification_status',
            sa.String(20),
            nullable=True,
            server_default=None,
        ),
    )
    op.add_column(
        'findings',
        sa.Column('url', sa.Text(), nullable=True),
    )
    # Índice para queries "mostrar só confirmed" e "quantos candidates por scan"
    op.create_index(
        'ix_findings_verification_status',
        'findings',
        ['verification_status'],
    )
    op.create_index(
        'ix_findings_scan_verification',
        'findings',
        ['scan_job_id', 'verification_status'],
    )


def downgrade() -> None:
    op.drop_index('ix_findings_scan_verification', table_name='findings')
    op.drop_index('ix_findings_verification_status', table_name='findings')
    op.drop_column('findings', 'url')
    op.drop_column('findings', 'verification_status')
