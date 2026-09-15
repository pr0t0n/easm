from alembic import op


revision = "0041_work_item_contract"
down_revision = "0040_attempt_fk_cascade"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("UPDATE scan_work_items SET profile = tool_name WHERE BTRIM(COALESCE(profile, '')) = ''")
    op.create_check_constraint(
        "ck_scan_work_items_profile_present",
        "scan_work_items",
        "BTRIM(profile) <> ''",
    )
    op.execute(
        """
        CREATE FUNCTION sync_terminal_work_item_attempt() RETURNS trigger AS $$
        DECLARE
            terminal_state text;
        BEGIN
            terminal_state := CASE NEW.status
                WHEN 'completed' THEN 'completed'
                WHEN 'done' THEN 'completed'
                WHEN 'failed' THEN 'failed'
                WHEN 'timeout' THEN 'timeout'
                WHEN 'skipped' THEN 'skipped'
                WHEN 'cancelled' THEN 'cancelled'
                WHEN 'canceled' THEN 'cancelled'
                ELSE NULL
            END;
            IF terminal_state IS NOT NULL AND OLD.status IS DISTINCT FROM NEW.status THEN
                UPDATE work_item_attempts
                SET state = terminal_state,
                    heartbeat_at = NOW(),
                    finished_at = COALESCE(finished_at, NOW()),
                    error_class = CASE
                        WHEN terminal_state IN ('completed', 'skipped', 'cancelled') THEN NULL
                        ELSE LEFT(COALESCE(NEW.last_error, terminal_state), 80)
                    END,
                    state_history = COALESCE(state_history, '[]'::jsonb) || jsonb_build_array(
                        jsonb_build_object(
                            'state', terminal_state,
                            'at', NOW(),
                            'source', 'scan_work_items_trigger'
                        )
                    )
                WHERE id = (
                    SELECT id
                    FROM work_item_attempts
                    WHERE work_item_id = NEW.id
                    ORDER BY id DESC
                    LIMIT 1
                )
                AND state IN ('execution_started', 'mcp_accepted', 'runner_started');
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_sync_terminal_work_item_attempt
        AFTER UPDATE OF status ON scan_work_items
        FOR EACH ROW
        EXECUTE FUNCTION sync_terminal_work_item_attempt();
        """
    )


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS trg_sync_terminal_work_item_attempt ON scan_work_items")
    op.execute("DROP FUNCTION IF EXISTS sync_terminal_work_item_attempt()")
    op.drop_constraint("ck_scan_work_items_profile_present", "scan_work_items", type_="check")
