-- When an allowed signup email was last sent a server invitation. The
-- invitation email allows one per address per week, so the self-host admin
-- refuses an earlier one instead of reporting a send that would be dropped.
-- NULL: never invited (or invited before this column existed).

ALTER TABLE selfhost_signup_allowlist
    ADD COLUMN IF NOT EXISTS last_invited_at TIMESTAMPTZ NULL;
