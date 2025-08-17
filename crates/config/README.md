# config

**Configuration Management Layer** - Settings, profiles, and configuration handling

Manages all configuration aspects of the SoftEther client.

## Core Components
- **Account Profiles**: VPN server connection profiles and credentials
- **Client Settings**: Application preferences and behavior configuration
- **Network Config**: Routing tables, DNS settings, and network policies
- **Security Policies**: Certificate validation, cipher preferences, security settings
- **Platform Config**: OS-specific configuration and integration settings

## Configuration Features

### Profile Management
- **Multiple Accounts**: Support for numerous VPN server profiles
- **Credential Storage**: Secure credential storage with OS keychain integration
- **Import/Export**: Configuration backup and sharing capabilities
- **Template System**: Pre-configured templates for common scenarios

### Advanced Configuration
- **Routing Control**: Custom routing tables and traffic splitting
- **DNS Management**: DNS server configuration and leak prevention
- **Proxy Settings**: HTTP/SOCKS proxy integration for complex networks
- **Quality of Service**: Bandwidth limiting and traffic prioritization

## Architecture Improvements

### Over C Implementation
- **Type Safety**: Strongly-typed configuration with compile-time validation
- **Immutable Config**: Immutable configuration structures prevent corruption
- **Schema Validation**: JSON Schema validation for configuration files
- **Live Reload**: Runtime configuration updates without restart

### Over Go Implementation
- **Rich Configuration**: Advanced settings vs minimal Go configuration
- **Validation Framework**: Comprehensive config validation and error reporting
- **Migration System**: Automatic configuration migration between versions
- **Enterprise Features**: Group policies, centralized management support

## Storage & Security
- **Encrypted Storage**: Configuration encryption for sensitive data
- **Keychain Integration**: OS credential storage (macOS Keychain, Windows Credential Store)
- **Access Control**: File permission management for configuration security
- **Audit Logging**: Configuration change tracking and auditing

## Platform Integration
- **Windows**: Registry integration, Group Policy support
- **macOS**: Preferences framework, Keychain services
- **Linux**: XDG config directories, system configuration
- **Mobile**: Platform-specific secure storage and configuration APIs
