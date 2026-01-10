//! Tunnel utilities for the VPN client.
//!
//! This module contains:
//! - Data loop state machine for tunnel operations
//! - Tunnel runner for the main data loop
//! - Shared packet processing logic
//! - Single-connection data loop
//! - Multi-connection data loop (half-connection mode)
//! - DHCP handling for tunnel setup

mod data_loop;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod dhcp_handler;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod multi_conn;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod packet_processor;
mod runner;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod single_conn;

pub use data_loop::{format_ip, DataLoopConfig, DataLoopState, Ipv4Info, LoopResult, TimingState};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub use packet_processor::*;
pub use runner::{RouteConfig, TunnelConfig, TunnelRunner};
