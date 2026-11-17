# selfhost

## What it is

Self-host mode for the authentication service: every account is fully entitled
(no plans or billing), the first account becomes root admin (`super_admin`),
new accounts pass a DB-backed signup policy, and admins manage accounts and
signups. Every admin action is audited. Off unless `MACRO_SELF_HOSTED=true`.

## Start here

- `src/domain/service.rs`: every rule (entitlements, root claim, signup policy, admin guards, auditing).
- `src/composition.rs`: the flag and the concrete wiring the service uses.

## Scope

- Owns: entitlement roles on account creation and startup backfill, root
  claim, signup policy and allowlist, server invitations to allowed emails
  (at most one per address per week, tracked in `last_invited_at`), the
  instance-wide view of workspace invite links and email invites (revoke,
  resend, resend inside the window), admin user listing, promotion,
  disabling, the admin audit log and its CSV export (`src/export.rs`).
- Not here: HTTP routes and the login/webhook hooks →
  `services/authentication_service/src/api/selfhost_admin.rs`; schema →
  `crates/macro_db_client/migrations/*_selfhost_*.sql`; workspace invite rules
  and emails → `crates/teams` (the immediate resend is
  `teams::domain::team_service::invite_resend`); the server invitation email →
  `invite_email::ServerInvite`.

## Boundaries

- Depends on: `roles_and_permissions` (role grants), `fusionauth`
  (deactivate/reactivate), `teams` and `entity_access` (workspace invites),
  `notification` and `invite_email` (the server invitation email, which has
  no referral code), MacroDB. Upstream crates are used through their `ports`
  features only.
- Used by: `authentication_service` only.

## Checks

- `cargo test -p selfhost` (domain tests use fakes; `outbound` tests need `DATABASE_URL`)
- Query or schema change: `nix develop --command just prepare_db`

## Gotchas

- Root is "some account holds `super_admin`"; the claim is serialized with an
  advisory lock, and the last active admin can't be demoted or disabled.
- Signup is open until root exists, so the very first account always gets in.
- Upstream merges: keep changes here; hooks in upstream files stay one-liners.
- Admin actions go through `run_audited`: a pending entry is written before the
  action runs, and if that write fails the action does not run. A new admin
  action needs an `AuditAction` variant and a domain test that it is recorded.
- `selfhost_audit_log` is append-only by trigger: no deletes, and a row only
  moves once from `pending` to its outcome.
- Workspace changes go through the teams service, never raw SQL:
  `outbound/teams.rs` issues a workspace-admin `EntityAccessReceipt` naming
  the instance admin, only after the domain confirmed that role. Reads of every
  workspace's links and invites query MacroDB directly.
- Fork additions inside upstream crates, kept additive for rebases:
  `teams/src/domain/team_service/invite_resend.rs` (+ its `mod` line),
  `SendNotificationRequest::with_email_outside_rate_limit` in `notification`,
  `invite_email/src/server_invite.rs` with `templates/server_invite.html`, and
  `ServerInvite` in `model_notifications`' digest block list.
