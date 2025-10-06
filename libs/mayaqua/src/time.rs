//! Time utilities for SoftEther VPN
//!
//! High-resolution timing functions compatible with SoftEther C implementation.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 64-bit millisecond timestamp (equivalent to C Tick64)
pub type Tick64 = u64;

/// Get current time as 64-bit millisecond timestamp
///
/// This is equivalent to the C implementation's Tick64() function
pub fn get_tick64() -> Tick64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

/// Get current time as seconds since Unix epoch
pub fn get_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// Convert milliseconds to Duration
pub fn millis_to_duration(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// Convert Duration to milliseconds
pub fn duration_to_millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}

/// Check if enough time has passed since last tick
pub fn is_interval_elapsed(last_tick: Tick64, interval_ms: u64) -> bool {
    let current = get_tick64();
    current.saturating_sub(last_tick) >= interval_ms
}

/// Sleep for specified milliseconds (async)
pub async fn sleep_millis(millis: u64) {
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

/// Sleep for specified seconds (async)
pub async fn sleep_secs(secs: u64) {
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

// Traffic monitoring and keep-alive intervals (from C implementation)
pub const TRAFFIC_CHECK_SPAN: u64 = 1000; // 1 second
pub const KEEPALIVE_INTERVAL: u64 = 30000; // 30 seconds
pub const SESSION_TIMEOUT: u64 = 60000; // 60 seconds

// Timeout constants (from Cedar.h)
pub const TIMEOUT_MIN: u64 = 5 * 1000; // 5 seconds minimum
pub const TIMEOUT_MAX: u64 = 60 * 1000; // 60 seconds maximum
pub const TIMEOUT_DEFAULT: u64 = 30 * 1000; // 30 seconds default
pub const CONNECTING_TIMEOUT: u64 = 15 * 1000; // 15 seconds connecting timeout
pub const KEEP_TCP_TIMEOUT: u64 = 1000; // 1 second TCP keep-alive

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tick64() {
        let tick1 = get_tick64();
        std::thread::sleep(Duration::from_millis(10));
        let tick2 = get_tick64();

        assert!(tick2 > tick1);
        assert!(tick2 - tick1 >= 10); // At least 10ms should have passed
    }

    #[test]
    fn test_get_time() {
        let time1 = get_time();
        let time2 = get_time();

        // Time should be moving forward (or equal if very fast)
        assert!(time2 >= time1);
    }

    #[test]
    fn test_is_interval_elapsed() {
        let now = get_tick64();

        // Interval should not be elapsed immediately
        assert!(!is_interval_elapsed(now, 1000));

        // Interval should be elapsed if we use an old timestamp
        let old_tick = now.saturating_sub(2000);
        assert!(is_interval_elapsed(old_tick, 1000));
    }

    #[test]
    fn test_duration_conversion() {
        let duration = Duration::from_millis(5000);
        let millis = duration_to_millis(duration);
        assert_eq!(millis, 5000);

        let converted_back = millis_to_duration(millis);
        assert_eq!(converted_back, duration);
    }

    #[test]
    fn test_constants() {
        assert_eq!(TIMEOUT_MIN, 5000);
        assert_eq!(TIMEOUT_DEFAULT, 30000);
        assert_eq!(TIMEOUT_MAX, 60000);
    }
}
