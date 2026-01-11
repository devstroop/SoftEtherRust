#!/bin/bash
# Build script for SoftEther VPN FFI library - Android
#
# This builds the Rust library for Android:
# - aarch64-linux-android (arm64-v8a)
# - armv7-linux-androideabi (armeabi-v7a)
# - x86_64-linux-android (x86_64)
# - i686-linux-android (x86)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

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
    log_info "Installing Android Rust targets..."
    rustup target add aarch64-linux-android
    rustup target add armv7-linux-androideabi
    rustup target add x86_64-linux-android
    rustup target add i686-linux-android
}

# Detect host OS for NDK toolchain path
get_ndk_host() {
    case "$(uname -s)" in
        Darwin)
            echo "darwin-x86_64"
            ;;
        Linux)
            echo "linux-x86_64"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            echo "windows-x86_64"
            ;;
        *)
            log_error "Unsupported host OS: $(uname -s)"
            exit 1
            ;;
    esac
}

# Get the linker extension for the host OS
get_linker_ext() {
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
            echo ".cmd"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Build for Android
build_android() {
    log_info "Building for Android..."
    
    # Check for Android NDK
    if [ -z "$ANDROID_NDK_HOME" ]; then
        log_error "ANDROID_NDK_HOME not set"
        log_info "Set it to your NDK path, e.g.:"
        log_info "  export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/25.0.8775105"
        log_info "  export ANDROID_NDK_HOME=~/Android/Sdk/ndk/25.0.8775105"
        exit 1
    fi
    
    NDK_HOST=$(get_ndk_host)
    LINKER_EXT=$(get_linker_ext)
    TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin"
    
    # Configure cargo LINKERS for Android
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android21-clang$LINKER_EXT"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$TOOLCHAIN/armv7a-linux-androideabi21-clang$LINKER_EXT"
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/x86_64-linux-android21-clang$LINKER_EXT"
    export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$TOOLCHAIN/i686-linux-android21-clang$LINKER_EXT"
    
    # Configure CC compilers for ring crate (TLS)
    export CC_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android21-clang$LINKER_EXT"
    export CC_armv7_linux_androideabi="$TOOLCHAIN/armv7a-linux-androideabi21-clang$LINKER_EXT"
    export CC_x86_64_linux_android="$TOOLCHAIN/x86_64-linux-android21-clang$LINKER_EXT"
    export CC_i686_linux_android="$TOOLCHAIN/i686-linux-android21-clang$LINKER_EXT"
    
    # Configure AR archivers
    export AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar"
    export AR_armv7_linux_androideabi="$TOOLCHAIN/llvm-ar"
    export AR_x86_64_linux_android="$TOOLCHAIN/llvm-ar"
    export AR_i686_linux_android="$TOOLCHAIN/llvm-ar"
    
    # Build for each architecture
    log_info "  Building aarch64-linux-android (arm64-v8a)..."
    cargo build --release --target aarch64-linux-android --features android
    
    log_info "  Building armv7-linux-androideabi (armeabi-v7a)..."
    cargo build --release --target armv7-linux-androideabi --features android
    
    log_info "  Building x86_64-linux-android (x86_64)..."
    cargo build --release --target x86_64-linux-android --features android
    
    log_info "  Building i686-linux-android (x86)..."
    cargo build --release --target i686-linux-android --features android
    
    # Create output directories
    mkdir -p target/android/jniLibs/arm64-v8a
    mkdir -p target/android/jniLibs/armeabi-v7a
    mkdir -p target/android/jniLibs/x86_64
    mkdir -p target/android/jniLibs/x86
    
    # Copy libraries
    cp target/aarch64-linux-android/release/libsoftether.so target/android/jniLibs/arm64-v8a/
    cp target/armv7-linux-androideabi/release/libsoftether.so target/android/jniLibs/armeabi-v7a/
    cp target/x86_64-linux-android/release/libsoftether.so target/android/jniLibs/x86_64/
    cp target/i686-linux-android/release/libsoftether.so target/android/jniLibs/x86/
    
    log_info "Android build complete: target/android/jniLibs/"
    
    # Copy to Android app if it exists
    if [ -d "../app/src/main" ]; then
        mkdir -p ../app/src/main/jniLibs/arm64-v8a
        mkdir -p ../app/src/main/jniLibs/armeabi-v7a
        mkdir -p ../app/src/main/jniLibs/x86_64
        mkdir -p ../app/src/main/jniLibs/x86
        cp target/android/jniLibs/arm64-v8a/libsoftether.so ../app/src/main/jniLibs/arm64-v8a/
        cp target/android/jniLibs/armeabi-v7a/libsoftether.so ../app/src/main/jniLibs/armeabi-v7a/
        cp target/android/jniLibs/x86_64/libsoftether.so ../app/src/main/jniLibs/x86_64/
        cp target/android/jniLibs/x86/libsoftether.so ../app/src/main/jniLibs/x86/
        log_info "Copied to Android app: app/src/main/jniLibs/"
    fi
}

# Build only arm64 (most common for modern devices)
build_android_arm64() {
    log_info "Building for Android (arm64 only)..."
    
    if [ -z "$ANDROID_NDK_HOME" ]; then
        log_error "ANDROID_NDK_HOME not set"
        exit 1
    fi
    
    NDK_HOST=$(get_ndk_host)
    LINKER_EXT=$(get_linker_ext)
    TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin"
    
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/aarch64-linux-android21-clang$LINKER_EXT"
    export CC_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android21-clang$LINKER_EXT"
    export AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar"
    
    log_info "  Building aarch64-linux-android (arm64-v8a)..."
    cargo build --release --target aarch64-linux-android --features android
    
    mkdir -p target/android/jniLibs/arm64-v8a
    cp target/aarch64-linux-android/release/libsoftether.so target/android/jniLibs/arm64-v8a/
    
    log_info "Android arm64 build complete: target/android/jniLibs/arm64-v8a/"
    
    # Copy to Android app if it exists
    if [ -d "../app/src/main" ]; then
        mkdir -p ../app/src/main/jniLibs/arm64-v8a
        cp target/android/jniLibs/arm64-v8a/libsoftether.so ../app/src/main/jniLibs/arm64-v8a/
        log_info "Copied to Android app: app/src/main/jniLibs/arm64-v8a/"
    fi
}

# Build only armv7 (32-bit ARM - older devices)
build_android_armv7() {
    log_info "Building for Android (armv7 only)..."
    
    if [ -z "$ANDROID_NDK_HOME" ]; then
        log_error "ANDROID_NDK_HOME not set"
        exit 1
    fi
    
    NDK_HOST=$(get_ndk_host)
    LINKER_EXT=$(get_linker_ext)
    TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin"
    
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$TOOLCHAIN/armv7a-linux-androideabi21-clang$LINKER_EXT"
    export CC_armv7_linux_androideabi="$TOOLCHAIN/armv7a-linux-androideabi21-clang$LINKER_EXT"
    export AR_armv7_linux_androideabi="$TOOLCHAIN/llvm-ar"
    
    log_info "  Building armv7-linux-androideabi (armeabi-v7a)..."
    cargo build --release --target armv7-linux-androideabi --features android
    
    mkdir -p target/android/jniLibs/armeabi-v7a
    cp target/armv7-linux-androideabi/release/libsoftether.so target/android/jniLibs/armeabi-v7a/
    
    log_info "Android armv7 build complete: target/android/jniLibs/armeabi-v7a/"
    
    # Copy to Android app if it exists
    if [ -d "../app/src/main" ]; then
        mkdir -p ../app/src/main/jniLibs/armeabi-v7a
        cp target/android/jniLibs/armeabi-v7a/libsoftether.so ../app/src/main/jniLibs/armeabi-v7a/
        log_info "Copied to Android app: app/src/main/jniLibs/armeabi-v7a/"
    fi
}

# Build for connected device automatically
build_android_auto() {
    log_info "Detecting connected device architecture..."
    
    if [ -z "$ANDROID_NDK_HOME" ]; then
        log_error "ANDROID_NDK_HOME not set"
        exit 1
    fi
    
    if ! command -v adb &> /dev/null; then
        log_error "adb not found. Install Android SDK platform-tools."
        exit 1
    fi
    
    ARCH=$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
    
    if [ -z "$ARCH" ]; then
        log_error "No device connected or adb not responding."
        exit 1
    fi
    
    log_info "Detected device architecture: $ARCH"
    
    case "$ARCH" in
        arm64-v8a)
            rustup target add aarch64-linux-android
            build_android_arm64
            ;;
        armeabi-v7a)
            rustup target add armv7-linux-androideabi
            build_android_armv7
            ;;
        x86_64)
            log_info "Building for x86_64..."
            rustup target add x86_64-linux-android
            NDK_HOST=$(get_ndk_host)
            LINKER_EXT=$(get_linker_ext)
            TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin"
            export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/x86_64-linux-android21-clang$LINKER_EXT"
            export CC_x86_64_linux_android="$TOOLCHAIN/x86_64-linux-android21-clang$LINKER_EXT"
            export AR_x86_64_linux_android="$TOOLCHAIN/llvm-ar"
            cargo build --release --target x86_64-linux-android --features android
            mkdir -p target/android/jniLibs/x86_64 ../app/src/main/jniLibs/x86_64
            cp target/x86_64-linux-android/release/libsoftether.so target/android/jniLibs/x86_64/
            cp target/android/jniLibs/x86_64/libsoftether.so ../app/src/main/jniLibs/x86_64/ 2>/dev/null || true
            ;;
        x86)
            log_info "Building for x86..."
            rustup target add i686-linux-android
            NDK_HOST=$(get_ndk_host)
            LINKER_EXT=$(get_linker_ext)
            TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin"
            export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$TOOLCHAIN/i686-linux-android21-clang$LINKER_EXT"
            export CC_i686_linux_android="$TOOLCHAIN/i686-linux-android21-clang$LINKER_EXT"
            export AR_i686_linux_android="$TOOLCHAIN/llvm-ar"
            cargo build --release --target i686-linux-android --features android
            mkdir -p target/android/jniLibs/x86 ../app/src/main/jniLibs/x86
            cp target/i686-linux-android/release/libsoftether.so target/android/jniLibs/x86/
            cp target/android/jniLibs/x86/libsoftether.so ../app/src/main/jniLibs/x86/ 2>/dev/null || true
            ;;
        *)
            log_error "Unknown architecture: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "Build complete for $ARCH"
}

# Print usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build    Build for all Android architectures"
    echo "  auto     Build for connected device (auto-detect arch)"
    echo "  arm64    Build for arm64-v8a only"
    echo "  armv7    Build for armeabi-v7a only (32-bit ARM)"
    echo "  clean    Clean Android build artifacts"
    echo ""
    echo "With no command, builds for all Android architectures."
    echo ""
    echo "Environment:"
    echo "  ANDROID_NDK_HOME  Path to Android NDK (required)"
}

# Main
check_tools

case "${1:-build}" in
    build|all)
        install_targets
        build_android
        ;;
    auto)
        build_android_auto
        ;;
    arm64)
        rustup target add aarch64-linux-android
        build_android_arm64
        ;;
    armv7)
        rustup target add armv7-linux-androideabi
        build_android_armv7
        ;;
    clean)
        log_info "Cleaning Android build artifacts..."
        rm -rf target/aarch64-linux-android
        rm -rf target/armv7-linux-androideabi
        rm -rf target/x86_64-linux-android
        rm -rf target/i686-linux-android
        rm -rf target/android
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
