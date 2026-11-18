-- Self-host administration: a single settings row, the signup allowlist, and
-- accounts disabled by an administrator. Only written when MACRO_SELF_HOSTED
-- is on; nothing reads these tables otherwise.
--
-- Idempotent: installs from before this migration was renumbered (it was
-- 20261110150956, a version upstream later reused) already have the tables.

CREATE TABLE IF NOT EXISTS selfhost_settings (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    signup_policy TEXT NOT NULL DEFAULT 'invite_only'
        CHECK (signup_policy IN ('open', 'invite_only')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NULL
);

CREATE TABLE IF NOT EXISTS selfhost_signup_allowlist (
    email TEXT PRIMARY KEY,
    added_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS selfhost_disabled_user (
    user_id TEXT PRIMARY KEY,
    disabled_by TEXT NOT NULL,
    disabled_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
