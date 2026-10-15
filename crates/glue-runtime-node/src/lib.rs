//! Stock Node executable provider and verified Node-API archive bridge.
mod bridge;
mod provider;
pub use provider::*;

pub const BRIDGE_REVISION: &str = "glue-node-api8-archive-v1";
pub const BOOTSTRAP: &str = include_str!("../support/bootstrap.cjs");
