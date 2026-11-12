//! Self-host domain: model, ports, and the service that enforces its rules.

pub mod model;
pub mod ports;
pub mod service;

#[cfg(test)]
mod test;
