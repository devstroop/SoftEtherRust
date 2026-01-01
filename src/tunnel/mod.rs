//! Tunnel utilities for the VPN client.
//!
//! This module contains:
//! - Data loop state machine for tunnel operations
//! - Tunnel runner for the main data loop

mod data_loop;
mod runner;

pub use runner::{TunnelRunner, TunnelConfig, RouteConfig};
pub use data_loop::{
    DataLoopState, DataLoopConfig, TimingState, LoopResult, Ipv4Info, format_ip,
};
