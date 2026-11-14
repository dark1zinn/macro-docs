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
  claim, signup policy and allowlist, admin user listing, promotion, disabling,
  the admin audit log and its CSV export (`src/export.rs`).
- Not here: HTTP routes and the login/webhook hooks →
  `services/authentication_service/src/api/selfhost_admin.rs`; schema →
  `crates/macro_db_client/migrations/*_selfhost_*.sql`.

## Boundaries

- Depends on: `roles_and_permissions` (role grants), `fusionauth` (deactivate/reactivate), MacroDB.
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
