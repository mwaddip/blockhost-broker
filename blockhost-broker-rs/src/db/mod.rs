//! Database module for IPAM and state management.

pub mod ipam;
mod models;

pub use ipam::Ipam;
pub use models::{Allocation, Token};
