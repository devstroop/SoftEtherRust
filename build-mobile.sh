#!/bin/bash
# Build script for SoftEther VPN FFI library
#
# This builds the Rust library for various targets:
# - iOS (aarch64-apple-ios, x86_64-apple-ios, aarch64-apple-ios-sim)
# - Android (aarch64-linux-android, armv7-linux-androideabi, x86_64-linux-android)
# - macOS (aarch64-apple-darwin, x86_64-apple-darwin)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

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
}

# Install required targets
install_targets() {
    log_info "Installing Rust targets..."
    
    case "$1" in
        ios)
            rustup target add aarch64-apple-ios
            rustup target add x86_64-apple-ios
            rustup target add aarch64-apple-ios-sim
            ;;
        android)
            rustup target add aarch64-linux-android
            rustup target add armv7-linux-androideabi
            rustup target add x86_64-linux-android
            rustup target add i686-linux-android
            ;;
        macos)
            rustup target add aarch64-apple-darwin
            rustup target add x86_64-apple-darwin
            ;;
        *)
            log_error "Unknown platform: $1"
            exit 1
            ;;
    esac
}

# Build for iOS
build_ios() {
    log_info "Building for iOS..."
    
    # Device (arm64)
    log_info "  Building aarch64-apple-ios..."
    cargo build --release --target aarch64-apple-ios --features ffi
    
    # Simulator (arm64 for Apple Silicon Macs)
    log_info "  Building aarch64-apple-ios-sim..."
    cargo build --release --target aarch64-apple-ios-sim --features ffi
    
    # Simulator (x86_64 for Intel Macs)
    log_info "  Building x86_64-apple-ios..."
    cargo build --release --target x86_64-apple-ios --features ffi
    
    # Create output directory
    mkdir -p target/ios
    
    # Create universal simulator library
    log_info "  Creating universal simulator library..."
    lipo -create \
        target/aarch64-apple-ios-sim/release/libsoftethervpn.a \
        target/x86_64-apple-ios/release/libsoftethervpn.a \
        -output target/ios/libsoftethervpn_sim.a
    
    # Copy device library
    cp target/aarch64-apple-ios/release/libsoftethervpn.a target/ios/libsoftethervpn_device.a
    
    # Create XCFramework
    log_info "  Creating XCFramework..."
    rm -rf target/ios/SoftEtherVPN.xcframework
    xcodebuild -create-xcframework \
        -library target/ios/libsoftethervpn_device.a -headers include \
        -library target/ios/libsoftethervpn_sim.a -headers include \
        -output target/ios/SoftEtherVPN.xcframework
    
    log_info "iOS build complete: target/ios/SoftEtherVPN.xcframework"
}

# Build for Android
build_android() {
    log_info "Building for Android..."
    
    # Check for Android NDK
    if [ -z "$ANDROID_NDK_HOME" ]; then
        log_error "ANDROID_NDK_HOME not set"
        log_info "Set it to your NDK path, e.g.:"
        log_info "  export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/25.0.8775105"
        exit 1
    fi
    
    # Configure cargo for Android
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi21-clang"
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android21-clang"
    export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android21-clang"
    
    # Build for each architecture
    log_info "  Building aarch64-linux-android (arm64-v8a)..."
    cargo build --release --target aarch64-linux-android --features ffi,jni
    
    log_info "  Building armv7-linux-androideabi (armeabi-v7a)..."
    cargo build --release --target armv7-linux-androideabi --features ffi,jni
    
    log_info "  Building x86_64-linux-android (x86_64)..."
    cargo build --release --target x86_64-linux-android --features ffi,jni
    
    log_info "  Building i686-linux-android (x86)..."
    cargo build --release --target i686-linux-android --features ffi,jni
    
    # Create output directories
    mkdir -p target/android/jniLibs/arm64-v8a
    mkdir -p target/android/jniLibs/armeabi-v7a
    mkdir -p target/android/jniLibs/x86_64
    mkdir -p target/android/jniLibs/x86
    
    # Copy libraries
    cp target/aarch64-linux-android/release/libsoftethervpn.so target/android/jniLibs/arm64-v8a/
    cp target/armv7-linux-androideabi/release/libsoftethervpn.so target/android/jniLibs/armeabi-v7a/
    cp target/x86_64-linux-android/release/libsoftethervpn.so target/android/jniLibs/x86_64/
    cp target/i686-linux-android/release/libsoftethervpn.so target/android/jniLibs/x86/
    
    log_info "Android build complete: target/android/jniLibs/"
}

# Build for macOS
build_macos() {
    log_info "Building for macOS..."
    
    # Apple Silicon
    log_info "  Building aarch64-apple-darwin..."
    cargo build --release --target aarch64-apple-darwin --features ffi
    
    # Intel
    log_info "  Building x86_64-apple-darwin..."
    cargo build --release --target x86_64-apple-darwin --features ffi
    
    # Create output directory
    mkdir -p target/macos
    
    # Create universal binary
    log_info "  Creating universal library..."
    lipo -create \
        target/aarch64-apple-darwin/release/libsoftethervpn.a \
        target/x86_64-apple-darwin/release/libsoftethervpn.a \
        -output target/macos/libsoftethervpn.a
    
    # Also create dynamic library
    lipo -create \
        target/aarch64-apple-darwin/release/libsoftethervpn.dylib \
        target/x86_64-apple-darwin/release/libsoftethervpn.dylib \
        -output target/macos/libsoftethervpn.dylib 2>/dev/null || true
    
    log_info "macOS build complete: target/macos/"
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
    cbindgen --config cbindgen.toml --crate softether-rust --output include/SoftEtherVPN_generated.h 2>/dev/null || true
    
    log_info "Headers generated in include/"
}

# Print usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  ios      Build for iOS (device + simulator)"
    echo "  android  Build for Android (all architectures)"
    echo "  macos    Build for macOS (universal)"
    echo "  all      Build for all platforms"
    echo "  headers  Generate C headers"
    echo "  clean    Clean build artifacts"
    echo ""
}

# Main
check_tools

case "${1:-}" in
    ios)
        install_targets ios
        build_ios
        ;;
    android)
        install_targets android
        build_android
        ;;
    macos)
        install_targets macos
        build_macos
        ;;
    all)
        install_targets ios
        install_targets android
        install_targets macos
        build_ios
        build_android
        build_macos
        ;;
    headers)
        generate_headers
        ;;
    clean)
        log_info "Cleaning build artifacts..."
        cargo clean
        rm -rf target/ios target/android target/macos
        ;;
    *)
        usage
        ;;
esac
