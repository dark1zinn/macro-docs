//! Self-host mode for Macro: every user is fully entitled, the first account
//! is the root admin, signup is governed by a database-backed policy, and
//! admins manage users and signups.
//!
//! The domain ([`domain`]) depends only on ports. Postgres, roles, and
//! FusionAuth adapters live in [`outbound`]. [`composition`] wires them and
//! reads the activation flag. HTTP routes live in `authentication_service`.

#![deny(missing_docs)]

pub mod composition;
pub mod domain;
pub mod outbound;
