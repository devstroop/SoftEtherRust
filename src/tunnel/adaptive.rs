//! Adaptive performance tuning for the VPN tunnel.
//!
//! Dynamically adjusts poll timeout and other parameters based on
//! measured traffic patterns to balance latency vs CPU usage.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

/// Adaptive tuning state shared between TUN reader and main loop.
pub struct AdaptiveTuning {
    /// Current poll timeout in milliseconds (1-10ms range).
    poll_timeout_ms: AtomicU32,
    /// Packets processed in current window.
    packets_this_window: AtomicU64,
    /// Window start time (unix millis for atomic storage).
    #[allow(dead_code)]
    window_start_ms: AtomicU64,
    /// Recent average packets per second.
    recent_pps: AtomicU32,
}

impl AdaptiveTuning {
    /// Create new adaptive tuning with default values.
    pub fn new() -> Self {
        let now_ms = Instant::now().elapsed().as_millis() as u64;
        Self {
            poll_timeout_ms: AtomicU32::new(1), // Start aggressive (1ms)
            packets_this_window: AtomicU64::new(0),
            window_start_ms: AtomicU64::new(now_ms),
            recent_pps: AtomicU32::new(0),
        }
    }

    /// Get current poll timeout in milliseconds.
    #[inline]
    pub fn poll_timeout_ms(&self) -> i32 {
        self.poll_timeout_ms.load(Ordering::Relaxed) as i32
    }

    /// Record a packet was processed and update tuning.
    /// Call this from the TUN reader for outgoing packets.
    #[inline]
    pub fn record_packet(&self) {
        self.packets_this_window.fetch_add(1, Ordering::Relaxed);
    }

    /// Update tuning based on recent traffic (call periodically from main loop).
    /// Returns current packets-per-second estimate.
    pub fn update(&self) -> u32 {
        let packets = self.packets_this_window.swap(0, Ordering::Relaxed);
        
        // Calculate PPS (assuming ~100ms window between updates)
        let pps = (packets * 10) as u32; // Rough estimate
        self.recent_pps.store(pps, Ordering::Relaxed);

        // Adaptive timeout based on traffic:
        // - High traffic (>1000 pps): 1ms for lowest latency
        // - Medium traffic (100-1000 pps): 2ms
        // - Low traffic (10-100 pps): 5ms  
        // - Idle (<10 pps): 10ms to save CPU
        let new_timeout = if pps > 1000 {
            1
        } else if pps > 100 {
            2
        } else if pps > 10 {
            5
        } else {
            10
        };

        self.poll_timeout_ms.store(new_timeout, Ordering::Relaxed);
        pps
    }

    /// Get recent packets-per-second estimate.
    pub fn recent_pps(&self) -> u32 {
        self.recent_pps.load(Ordering::Relaxed)
    }

    /// Check if we're in high-throughput mode.
    #[inline]
    pub fn is_high_throughput(&self) -> bool {
        self.recent_pps.load(Ordering::Relaxed) > 500
    }
}

impl Default for AdaptiveTuning {
    fn default() -> Self {
        Self::new()
    }
}

/// Adaptive channel that tracks backpressure.
pub struct ChannelStats {
    /// Successful sends.
    sends: AtomicU64,
    /// Channel-full events (backpressure).
    backpressure_events: AtomicU64,
}

impl ChannelStats {
    pub fn new() -> Self {
        Self {
            sends: AtomicU64::new(0),
            backpressure_events: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_send(&self) {
        self.sends.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_backpressure(&self) {
        self.backpressure_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Get backpressure ratio (0.0 = none, 1.0 = always blocked).
    pub fn backpressure_ratio(&self) -> f32 {
        let sends = self.sends.load(Ordering::Relaxed);
        let bp = self.backpressure_events.load(Ordering::Relaxed);
        if sends == 0 {
            0.0
        } else {
            bp as f32 / (sends + bp) as f32
        }
    }

    /// Reset stats for new measurement window.
    pub fn reset(&self) {
        self.sends.store(0, Ordering::Relaxed);
        self.backpressure_events.store(0, Ordering::Relaxed);
    }
}

impl Default for ChannelStats {
    fn default() -> Self {
        Self::new()
    }
}
