#!/bin/bash
# Build script for SoftEther VPN FFI library - iOS
#
# This builds the Rust library for iOS:
# - aarch64-apple-ios (device only)
# Note: Simulator builds skipped - Network Extension doesn't work on simulator
#
# Output is placed directly in the parent WorxVPN-iOS project:
# - ../Frameworks/SoftEtherVPN.xcframework
# - ../WorxVPNExtension/SoftEtherVPN.h

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Project root is parent of SoftEtherRust submodule
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for required tools
check_tools() {
    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found. Install Rust: https://rustup.rs"
        exit 1
    fi
    
    if ! command -v rustup &> /dev/null; then
        log_error "rustup not found. Install from: https://rustup.rs"
        exit 1
    fi
    
    if ! command -v xcodebuild &> /dev/null; then
        log_error "xcodebuild not found. Install Xcode from the App Store"
        exit 1
    fi
}

# Install required targets
install_targets() {
    log_info "Installing iOS Rust targets..."
    rustup target add aarch64-apple-ios
}

# Build for iOS
build_ios() {
    log_info "Building for iOS (device only)..."
    log_info "  Note: Simulator builds skipped - Network Extension not supported"
    
    # Set minimum iOS deployment target to match Xcode project (15.0)
    export IPHONEOS_DEPLOYMENT_TARGET=15.0
    
    # Device (arm64)
    log_info "  Building aarch64-apple-ios..."
    cargo build --release --target aarch64-apple-ios --features ffi
    
    # Create output directory
    mkdir -p target/ios
    
    # Copy device library
    cp target/aarch64-apple-ios/release/libsoftether.a target/ios/libsoftether.a
    
    # Create XCFramework (device only)
    log_info "  Creating XCFramework..."
    rm -rf target/ios/SoftEtherVPN.xcframework
    xcodebuild -create-xcframework \
        -library target/ios/libsoftether.a -headers include \
        -output target/ios/SoftEtherVPN.xcframework
    
    log_info "iOS build complete: target/ios/SoftEtherVPN.xcframework"
    
    # Copy to WorxVPN-iOS project
    log_info "Installing to WorxVPN-iOS project..."
    
    # Create Frameworks directory if needed
    mkdir -p "$PROJECT_ROOT/Frameworks"
    
    # Copy XCFramework
    rm -rf "$PROJECT_ROOT/Frameworks/SoftEtherVPN.xcframework"
    cp -R target/ios/SoftEtherVPN.xcframework "$PROJECT_ROOT/Frameworks/"
    log_info "  Copied XCFramework to Frameworks/"
    
    # Copy header to extension
    cp include/SoftEtherVPN.h "$PROJECT_ROOT/WorxVPNExtension/"
    log_info "  Copied SoftEtherVPN.h to WorxVPNExtension/"
    
    log_info "Installation complete!"
}

# Generate headers
generate_headers() {
    log_info "Generating C headers..."
    
    # Install cbindgen if needed
    if ! command -v cbindgen &> /dev/null; then
        log_info "Installing cbindgen..."
        cargo install cbindgen
    fi
    
    # Generate header
    cbindgen --config cbindgen.toml --crate softether --output include/SoftEtherVPN_generated.h 2>/dev/null || true
    
    log_info "Headers generated in include/"
}

# Print usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build    Build for iOS device"
    echo "  headers  Generate C headers"
    echo "  clean    Clean iOS build artifacts"
    echo ""
    echo "With no command, builds for iOS device."
}

# Main
check_tools

case "${1:-build}" in
    build)
        install_targets
        build_ios
        ;;
    headers)
        generate_headers
        ;;
    clean)
        log_info "Cleaning iOS build artifacts..."
        rm -rf target/aarch64-apple-ios
        rm -rf target/ios
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        log_error "Unknown command: $1"
        usage
        exit 1
        ;;
esac
