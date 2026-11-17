-- When an allowed signup email was last sent a server invitation. The
-- self-host admin sends one per address per week and refuses an earlier one,
-- telling the admin when the next can go out.
-- NULL: never invited (or invited before this column existed).

ALTER TABLE selfhost_signup_allowlist
    ADD COLUMN IF NOT EXISTS last_invited_at TIMESTAMPTZ NULL;
