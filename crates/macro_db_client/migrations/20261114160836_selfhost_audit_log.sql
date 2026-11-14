-- Self-host admin audit log. An entry is written before an admin action runs
-- (status 'pending') and settled once its outcome is known. Rows are never
-- deleted, and only a pending row may change, once, to its outcome.
CREATE TABLE IF NOT EXISTS selfhost_audit_log (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Macro user id of the admin; NULL for actions the system takes itself.
    actor TEXT,
    action TEXT NOT NULL,
    -- What the action applies to: a profile id or an email.
    target TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'succeeded', 'failed')),
    -- Why a failed action failed.
    error TEXT,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS selfhost_audit_log_action_idx
    ON selfhost_audit_log (action, id DESC);
CREATE INDEX IF NOT EXISTS selfhost_audit_log_actor_idx
    ON selfhost_audit_log (actor, id DESC);

CREATE OR REPLACE FUNCTION selfhost_audit_log_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'selfhost_audit_log is append-only';
    END IF;
    IF OLD.status <> 'pending'
        OR NEW.status = 'pending'
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.actor IS DISTINCT FROM OLD.actor
        OR NEW.action IS DISTINCT FROM OLD.action
        OR NEW.target IS DISTINCT FROM OLD.target
        OR NEW.details IS DISTINCT FROM OLD.details
    THEN
        RAISE EXCEPTION 'selfhost_audit_log entries only move from pending to an outcome';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS selfhost_audit_log_append_only ON selfhost_audit_log;
CREATE TRIGGER selfhost_audit_log_append_only
    BEFORE UPDATE OR DELETE ON selfhost_audit_log
    FOR EACH ROW EXECUTE FUNCTION selfhost_audit_log_append_only();
