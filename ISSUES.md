# Issues & TODO

## 1. Critical

_No critical issues._

---

## 2. iOS Integration

_All iOS integration issues resolved._

---

## 3. Android

_All Android issues resolved._

---

## 4. Protocol

### 4.1 UDP Acceleration Data Path Not Integrated
- ✅ UDP accel params now sent during authentication (when `udp_accel: true`)
- ✅ Server UDP accel response is parsed and logged
- ❌ UDP data path NOT integrated into tunnel runner
- ❌ No fallback/upgrade to UDP when available
- Note: Auth negotiation is complete, but actual UDP send/recv requires tunnel runner changes
- Official C: `UdpAccel` integrated with `SessionMain()`, parallel send/recv paths

---

## 5. Performance

### 5.1 Packet Statistics Not Incremented (FFI)
- `bytes_sent`, `bytes_received`, `packets_sent`, `packets_received` not updated in packet loop
- Only `packets_dropped` and `uptime_secs` work correctly
- Impact: Low - stats API returns zeros for traffic counters

### 5.2 ARP / Gateway MAC Learning ✅ RESOLVED
- ✅ Desktop learns gateway MAC via ARP responses
- ✅ Mobile now sends gratuitous ARP and gateway ARP request at tunnel start
- ✅ Incoming ARP packets processed to learn gateway MAC
- ✅ Outgoing frames rewritten to use learned gateway MAC (falls back to broadcast if not learned)
- Impact: Resolved - full parity with desktop ARP behavior

### 5.3 QoS Packet Prioritization ✅ RESOLVED
- ✅ `qos` config flag is parsed and sent to server
- ✅ QoS module implemented (src/packet/qos.rs) with `is_priority_packet()` function
- ✅ Priority detection matches official SoftEther: IPv4 ToS != 0, ICMP, VoIP ports
- ✅ IPv6 traffic class and ICMPv6 also prioritized
- ✅ FFI packet loop sorts priority packets to front when QoS enabled
- Impact: Resolved - VoIP/real-time packets sent first in batch transmissions

---

## 6. Half-Connection Mode

_All half-connection mode issues resolved._

---

## 7. Resolved

- ✅ Compression latency (switched to fast level)
- ✅ Android socket protection
- ✅ DHCP through tunnel
- ✅ C header state enum fixed
- ✅ Half-connection mode direction parsing (TcpDirection enum)
- ✅ RC4 Tunnel Encryption (src/crypto/rc4.rs with streaming cipher)
- ✅ RC4 Key Pair parsing from server Welcome packet
- ✅ RC4 integration in tunnel TX/RX paths (single-conn Unix & Windows)
- ✅ Swift bridge field name mismatches fixed (skip_tls_verify, timeout_seconds, mtu, etc.)
- ✅ Swift bridge missing fields added (useEncrypt, udpAccel, qos, natTraversal, routing)
- ✅ Swift Session mac_address and gateway_mac added
- ✅ Swift log callback wired (on_log)
- ✅ Kotlin bridge all config options exposed (MTU, encrypt, udpAccel, qos, routing)
- ✅ Kotlin Session now includes macAddress from session
- ✅ VpnService uses session MAC instead of hardcoded
- ✅ Kotlin log callback and socket protection callback added
- ✅ UseSSLDataEncryption flag handled (skip RC4 when no keys present)
- ✅ NAT-T port keepalive signaling implemented (encode_keepalive_with_nat_t)
- ✅ Compression switched to fast level for low latency
- ✅ Tokio worker threads reduced to 1 for mobile battery
- ✅ Certificate pinning implemented (custom CA PEM and SHA-256 fingerprint verification)
- ✅ Packet queue backpressure implemented (QueueFull result code, dropped packet stats)
- ✅ UDP acceleration auth flow wired (params sent, server response parsed)
- ✅ FIFO buffer pre-allocation (compress_into for zero-alloc hot path, pre-alloc comp_buf)
- ✅ iOS socket protection via setsockopt(SO_NET_SERVICE_TYPE, NET_SERVICE_TYPE_VV)
- ✅ RC4 encryption in FFI/mobile packet loop (TunnelEncryption with encrypt/decrypt)
- ✅ Android IP exclusion callback (exclude_ip for cluster redirects)
- ✅ iOS IP exclusion callback (exclude_ip wired to Swift onExcludeIp)
- ✅ Multi-connection support for mobile (establish_additional_connections after DHCP)
- ✅ Half-connection mode for mobile (auto-enabled when max_connections > 1)
- ✅ Android TLS cert pinning (custom_ca_pem and cert_fingerprint_sha256 wired in JNI)
- ✅ Keepalive encryption (RC4 applied to keepalive packets on mobile)
- ✅ Half-connection mode direction verified (TcpDirection 0=Both, 1=ServerToClient, 2=ClientToServer matches official C; primary always ClientToServer; can_send/can_recv filters connections correctly)
- ✅ DHCPv6 integration for FFI/mobile (perform_dhcpv6 after DHCPv4, session includes ipv6_address/dns1_v6/dns2_v6)
- ✅ Reconnection logic for FFI/mobile (retry with 10s delay for UserAlreadyLoggedIn, up to 5 attempts)
- ✅ ARP/Gateway MAC learning for FFI/mobile (GARP + gateway request sent, ARP replies processed, outgoing frames use learned MAC)
- ✅ QoS packet prioritization (is_priority_packet() detects ToS/DSCP, ICMP, VoIP ports; FFI sorts priority packets first)
