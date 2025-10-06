# cedar

**VPN Engine Layer** - Core VPN protocol and session management

Based on the original SoftEther Cedar module, this is the heart of the VPN functionality.

## Core Components
- **Session Management**: VPN session lifecycle, state machines, and connection handling
  - **Session Constants**: MAX_SESSION_NAME_LEN=255, MAX_CONNECTION_NAME_LEN=255
  - **Server Limits**: SERVER_MAX_SESSIONS=4096, SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION=100000
  - **Per-IP Limits**: DEFAULT_MAX_CONNECTIONS_PER_IP=256, MIN_MAX_CONNECTIONS_PER_IP=10
  - **NAT Limits**: NAT_MAX_SESSIONS=4096, NAT_MAX_SESSIONS_KERNEL=65536
  
- **Authentication**: Multiple auth methods (password, certificate, RADIUS, etc.)
  - **Auth Types** (from Cedar.h):
    - `AUTHTYPE_ANONYMOUS = 0` - Anonymous authentication
    - `AUTHTYPE_PASSWORD = 1` - Password authentication  
    - `AUTHTYPE_USERCERT = 2` - User certificate authentication
    - `AUTHTYPE_ROOTCERT = 3` - Root certificate from trusted CA
    - `AUTHTYPE_RADIUS = 4` - RADIUS authentication
    - `AUTHTYPE_NT = 5` - Windows NT authentication
    - `AUTHTYPE_OPENVPN_CERT = 98` - TLS client certificate
    - `AUTHTYPE_TICKET = 99` - Ticket authentication
    
  - **Client Auth Types**:
    - `CLIENT_AUTHTYPE_ANONYMOUS = 0` - Anonymous authentication
    - `CLIENT_AUTHTYPE_PASSWORD = 1` - Password authentication
    - `CLIENT_AUTHTYPE_PLAIN_PASSWORD = 2` - Plain password authentication
    - `CLIENT_AUTHTYPE_CERT = 3` - Certificate authentication
    - `CLIENT_AUTHTYPE_SECURE = 4` - Secure device authentication
- **Connection Pool**: Multi-connection support for load balancing and redundancy  
- **Keep-Alive**: Connection monitoring and automatic reconnection
- **Traffic Control**: Bandwidth limiting, QoS, and flow control

## Session Types and Modes (from Session.h)
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum SessionMode {
    LocalHostSession,    // Local host session
    ServerMode,          // Server mode session
    NormalClient,        // Regular client (not localbridge)
    LinkModeClient,      // Link mode client
    LinkModeServer,      // Link mode server
    SecureNATMode,       // SecureNAT session
    BridgeMode,          // Bridge session
    VirtualHost,         // Virtual host mode
    L3SwitchMode,        // Layer-3 switch mode
    InProcMode,          // In-process mode
}

// Session limits and constraints
const MAX_SESSION_NAME_LEN: usize = 255;
const MAX_CONNECTION_NAME_LEN: usize = 255;
const SERVER_MAX_SESSIONS: u32 = 4096;
const SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION: u32 = 100000;
const NAT_MAX_SESSIONS: u32 = 4096;
const NAT_MAX_SESSIONS_KERNEL: u32 = 65536;
const DEFAULT_MAX_CONNECTIONS_PER_IP: u32 = 256;
const MIN_MAX_CONNECTIONS_PER_IP: u32 = 10;
```

## Protocol Implementation
- **SoftEther Protocol**: Native SoftEther VPN protocol implementation
- **Packet Processing**: Encryption, compression, and packet transformation
- **Hub Communication**: Virtual hub connection and management
- **Farm Redirection**: Server farm and load balancer support

## Key Improvements over C Implementation
- **Async Architecture**: Full async/await implementation for better concurrency
- **Type-Safe State**: Enum-based state machines prevent invalid transitions
- **Channel-Based Communication**: Use Rust channels instead of callback-heavy architecture
- **Modular Design**: Clear separation between protocol, session, and connection concerns

## Architecture Differences from Go Implementation
- **Multi-Connection**: Support for connection bonding (vs Go's single connection)
- **Enterprise Features**: Auto-reconnect, traffic monitoring, advanced auth methods
- **Production Ready**: Error recovery, resource management, and monitoring capabilities
