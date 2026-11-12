# selfhost

## What it is

Self-host mode for the authentication service: every account is fully entitled
(no plans or billing), the first account becomes root admin (`super_admin`),
new accounts pass a DB-backed signup policy, and admins manage accounts and
signups. Off unless `MACRO_SELF_HOSTED=true`.

## Start here

- `src/domain/service.rs`: every rule (entitlements, root claim, signup policy, admin guards).
- `src/composition.rs`: the flag and the concrete wiring the service uses.

## Scope

- Owns: entitlement roles on account creation and startup backfill, root
  claim, signup policy and allowlist, admin user listing, promotion, disabling.
- Not here: HTTP routes and the login/webhook hooks →
  `services/authentication_service/src/api/selfhost_admin.rs`; schema →
  `crates/macro_db_client/migrations/*_selfhost_admin.sql`.

## Boundaries

- Depends on: `roles_and_permissions` (role grants), `fusionauth` (deactivate/reactivate), MacroDB.
- Used by: `authentication_service` only.

## Checks

- `cargo test -p selfhost` (domain tests use fakes; no DB needed)
- Query or schema change: `nix develop --command just prepare_db`

## Gotchas

- Root is "some account holds `super_admin`"; the claim is serialized with an
  advisory lock, and the last active admin can't be demoted or disabled.
- Signup is open until root exists, so the very first account always gets in.
- Upstream merges: keep changes here; hooks in upstream files stay one-liners.
