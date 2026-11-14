//! Self-host mode for Macro: every user is fully entitled, the first account
//! is the root admin, signup is governed by a database-backed policy, and
//! admins manage users and signups. Every admin action is audited.
//!
//! The domain ([`domain`]) depends only on ports. Postgres, roles, and
//! FusionAuth adapters live in [`outbound`]. [`composition`] wires them and
//! reads the activation flag. HTTP routes live in `authentication_service`;
//! [`export`] renders what they download.

#![deny(missing_docs)]

pub mod composition;
pub mod domain;
pub mod export;
pub mod outbound;
