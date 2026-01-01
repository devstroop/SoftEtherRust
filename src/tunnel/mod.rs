//! Tunnel utilities for the VPN client.
//!
//! This module contains:
//! - Data loop state machine for tunnel operations
//! - Tunnel runner for the main data loop

mod data_loop;
mod runner;

pub use data_loop::{format_ip, DataLoopConfig, DataLoopState, Ipv4Info, LoopResult, TimingState};
pub use runner::{RouteConfig, TunnelConfig, TunnelRunner};
