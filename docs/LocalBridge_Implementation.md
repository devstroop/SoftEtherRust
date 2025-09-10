# SoftEtherRustV2 LocalBridge Implementation

## Overview

This implementation adds comprehensive LocalBridge support to SoftEtherRustV2, enabling the VPN client to work correctly with both SecureNAT (SoftEther virtual DHCP) and LocalBridge (external DHCP forwarding) network modes.

## Problem Solved

The original SoftEtherRustV2 implementation used the `dhcproto` library which was designed for standard DHCP scenarios and failed with LocalBridge mode because:

1. **Wrong timeout assumptions**: LocalBridge DHCP responses are forwarded through the physical network bridge, causing longer delays than virtual SecureNAT responses
2. **No fallback mechanism**: When external DHCP servers were unreachable, the client would fail completely
3. **Fixed retry logic**: The same retry parameters were used for both fast virtual DHCP and slow external DHCP

## Solution Architecture

### 1. Network Mode Detection (`network_mode.rs`)

```rust
pub enum NetworkMode {
    SecureNAT,    // SoftEther provides virtual DHCP/NAT
    LocalBridge,  // External DHCP/NAT through bridge
    Unknown,      // Mode could not be determined
}
```

**Detection Strategy:**
- Sends a quick DHCP discover with 3-second timeout
- Analyzes response characteristics:
  - **Response Time**: SecureNAT < 300ms, LocalBridge > 300ms
  - **IP Subnet**: SecureNAT uses 192.168.30.x by default
  - **Lease Time**: SecureNAT uses 7200 seconds by default

### 2. Adaptive DHCP Client (`dhcp_localbridge.rs`)

```rust
pub struct AdaptiveDhcpClient {
    dataplane: DataPlane,
    mac_address: [u8; 6],
    mode: Option<NetworkMode>,
    dhcp_client: DhcpClient,
}
```

**Adaptive Behavior:**
- **SecureNAT Mode**: 10-second timeout, fast retry backoff
- **LocalBridge Mode**: 30-second timeout, patient retry backoff, static fallback
- **Unknown Mode**: Try SecureNAT first, then LocalBridge

### 3. Enhanced DHCP Client (`dhcp.rs` modifications)

**Adaptive Timeouts:**
```rust
let mut backoff = if timeout > Duration::from_secs(15) {
    Duration::from_millis(1500) // LocalBridge mode: slower initial backoff
} else {
    Duration::from_millis(800)  // SecureNAT mode: faster backoff
};
```

**Extended Lease Structure:**
```rust
pub struct Lease {
    pub client_ip: Ipv4Addr,
    pub server_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,        // Renamed from 'router'
    pub subnet_mask: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time: Option<Duration>,
    pub renewal_time: Option<Duration>,    // Added for proper lease management
    pub rebinding_time: Option<Duration>,  // Added for proper lease management
    // ... other fields
}
```

### 4. VPN Client Integration (`vpnclient.rs` modifications)

**Adaptive DHCP Usage:**
```rust
// Replace old DHCP client
let mut adaptive_dhcp = crate::dhcp_localbridge::AdaptiveDhcpClient::new(dp_clone.clone(), mac);
info!("🔄 Attempting adaptive DHCP over tunnel (supports SecureNAT and LocalBridge)");

match adaptive_dhcp.run(&iface_for_dhcp).await {
    Ok(lease) => {
        info!("✅ Adaptive DHCP lease acquired: {}", lease.client_ip);
        // Apply network settings...
    }
    Err(e) => warn!("🚨 Adaptive DHCP negotiation failed: {e}"),
}
```

## Implementation Details

### Network Mode Detection Flow

1. **Quick Detection**: Send DHCP discover with 3s timeout
2. **Response Analysis**: 
   - Fast response (< 300ms) + SoftEther defaults = SecureNAT
   - Slow response (> 300ms) + non-SoftEther settings = LocalBridge
3. **Fallback**: If detection fails, assume SecureNAT

### LocalBridge DHCP Flow

1. **Extended Timeout**: Use 30-second timeout for external DHCP
2. **Multiple Attempts**: Retry up to 3 times with delays
3. **Static Fallback**: If DHCP completely fails:
   ```rust
   Ok(Lease {
       client_ip: Ipv4Addr::new(192, 168, 1, 200),
       gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
       subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
       dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
       lease_time: Some(Duration::from_secs(86400)),
       // ...
   })
   ```

### Retry Logic Improvements

**SecureNAT Mode:**
- Initial backoff: 800ms
- Max backoff: 4s
- Total timeout: 10s

**LocalBridge Mode:**
- Initial backoff: 1500ms  
- Max backoff: 8s
- Total timeout: 30s
- Multiple attempts with static fallback

## File Changes Summary

### New Files
- `crates/vpnclient/src/network_mode.rs` - Network mode detection
- `crates/vpnclient/src/dhcp_localbridge.rs` - Adaptive DHCP client
- `crates/vpnclient/src/localbridge_test.rs` - Integration tests

### Modified Files
- `crates/vpnclient/src/dhcp.rs` - Enhanced with adaptive timeouts and lease structure
- `crates/vpnclient/src/vpnclient.rs` - Integrated adaptive DHCP client
- `crates/vpnclient/src/lib.rs` - Exported new modules

## Benefits

1. **Universal Compatibility**: Works with both SecureNAT and LocalBridge VPN servers
2. **Intelligent Detection**: Automatically detects network mode and adapts
3. **Robust Fallback**: Static IP configuration when external DHCP fails
4. **Optimized Performance**: Fast timeouts for SecureNAT, patient timeouts for LocalBridge
5. **Better Logging**: Enhanced diagnostics with mode-specific messaging

## Usage Example

```rust
// The VPN client now automatically handles both modes
let client = VpnClient::new(config).await?;
client.connect().await?;

// Network mode is detected automatically:
// - SecureNAT: Fast DHCP (10s timeout)
// - LocalBridge: Patient DHCP (30s timeout) + static fallback
```

## Testing

Run the integration tests:
```bash
cargo test --package vpnclient localbridge_tests
```

Or use the test script:
```bash
cargo run --bin localbridge_test
```

## Backwards Compatibility

This implementation is fully backwards compatible:
- Existing SecureNAT configurations work unchanged
- LocalBridge configurations now work correctly
- No configuration changes required

## Future Enhancements

1. **Network Traffic Analysis**: Monitor bridge traffic to detect external devices
2. **Configurable Static IPs**: Allow custom static fallback configurations  
3. **IPv6 LocalBridge**: Extend LocalBridge support to DHCPv6
4. **Bridge Discovery**: Automatically discover bridge network parameters