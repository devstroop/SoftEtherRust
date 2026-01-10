# SoftEtherRust Build Guide

> Complete build instructions for all platforms and architectures.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Android Build](#android-build)
- [iOS Build](#ios-build)
- [Desktop Build](#desktop-build)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Verify Installation

```bash
rustc --version
cargo --version
rustup --version
```

---

## Android Build

### Step 1: Install Android NDK

**Option A: Via Android Studio**
1. Open Android Studio → Settings → SDK Manager
2. SDK Tools tab → Check "NDK (Side by side)"
3. Install NDK version 25.x or higher

**Option B: Via Command Line**
```bash
# macOS
sdkmanager "ndk;25.1.8937393"

# Linux
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "ndk;25.1.8937393"
```

### Step 2: Set Environment Variables

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
# Android SDK & NDK
export ANDROID_HOME="$HOME/Library/Android/sdk"           # macOS
# export ANDROID_HOME="$HOME/Android/Sdk"                 # Linux

export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/25.1.8937393"  # Adjust version as needed

# Detect host OS
case "$(uname -s)" in
    Darwin) NDK_HOST="darwin-x86_64" ;;
    Linux)  NDK_HOST="linux-x86_64" ;;
    *)      NDK_HOST="windows-x86_64" ;;
esac

# Android toolchain paths
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin:$PATH"

# Cargo linkers for each Android architecture
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/aarch64-linux-android21-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/armv7a-linux-androideabi21-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/x86_64-linux-android21-clang"
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/i686-linux-android21-clang"

# CC compilers for ring crate (required for TLS)
export CC_aarch64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/aarch64-linux-android21-clang"
export CC_armv7_linux_androideabi="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/armv7a-linux-androideabi21-clang"
export CC_x86_64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/x86_64-linux-android21-clang"
export CC_i686_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/i686-linux-android21-clang"

# AR archivers
export AR_aarch64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/llvm-ar"
export AR_armv7_linux_androideabi="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/llvm-ar"
export AR_x86_64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/llvm-ar"
export AR_i686_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin/llvm-ar"
```

**Reload shell:**
```bash
source ~/.zshrc  # or ~/.bashrc
```

### Step 3: Install Rust Targets

```bash
# Install all Android targets
rustup target add aarch64-linux-android      # arm64-v8a (64-bit ARM)
rustup target add armv7-linux-androideabi    # armeabi-v7a (32-bit ARM)
rustup target add x86_64-linux-android       # x86_64 (64-bit Intel)
rustup target add i686-linux-android         # x86 (32-bit Intel)
```

### Step 4: Check Your Device Architecture

```bash
adb shell getprop ro.product.cpu.abi
```

| Output | Architecture | Rust Target |
|--------|--------------|-------------|
| `arm64-v8a` | 64-bit ARM | `aarch64-linux-android` |
| `armeabi-v7a` | 32-bit ARM | `armv7-linux-androideabi` |
| `x86_64` | 64-bit Intel | `x86_64-linux-android` |
| `x86` | 32-bit Intel | `i686-linux-android` |

### Step 5: Build for Your Architecture

**For armeabi-v7a (32-bit ARM):**
```bash
cd SoftEtherRust
cargo build --release --target armv7-linux-androideabi --features android
```

**For arm64-v8a (64-bit ARM):**
```bash
cd SoftEtherRust
cargo build --release --target aarch64-linux-android --features android
```

**For x86_64:**
```bash
cd SoftEtherRust
cargo build --release --target x86_64-linux-android --features android
```

**For x86:**
```bash
cd SoftEtherRust
cargo build --release --target i686-linux-android --features android
```

**Build ALL architectures:**
```bash
cd SoftEtherRust
cargo build --release --target aarch64-linux-android --features android
cargo build --release --target armv7-linux-androideabi --features android
cargo build --release --target x86_64-linux-android --features android
cargo build --release --target i686-linux-android --features android
```

### Step 6: Copy Libraries to Android App

```bash
# Create jniLibs directories
mkdir -p ../app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

# Copy libraries (only copy the ones you built)
cp target/aarch64-linux-android/release/libsoftether.so ../app/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libsoftether.so ../app/src/main/jniLibs/armeabi-v7a/
cp target/x86_64-linux-android/release/libsoftether.so ../app/src/main/jniLibs/x86_64/
cp target/i686-linux-android/release/libsoftether.so ../app/src/main/jniLibs/x86/
```

### Step 7: Build and Install APK

```bash
cd ..  # Back to WorxVPN-Android root
./gradlew installDebug
```

---

## Quick Build Commands

### Build for your device only (faster)

```bash
# Check device arch first
ARCH=$(adb shell getprop ro.product.cpu.abi)
echo "Device architecture: $ARCH"

cd SoftEtherRust

case "$ARCH" in
    arm64-v8a)
        TARGET="aarch64-linux-android"
        JNI_DIR="arm64-v8a"
        ;;
    armeabi-v7a)
        TARGET="armv7-linux-androideabi"
        JNI_DIR="armeabi-v7a"
        ;;
    x86_64)
        TARGET="x86_64-linux-android"
        JNI_DIR="x86_64"
        ;;
    x86)
        TARGET="i686-linux-android"
        JNI_DIR="x86"
        ;;
esac

echo "Building for $TARGET..."
cargo build --release --target $TARGET --features android

mkdir -p ../app/src/main/jniLibs/$JNI_DIR
cp target/$TARGET/release/libsoftether.so ../app/src/main/jniLibs/$JNI_DIR/

cd ..
./gradlew installDebug
```

---

## iOS Build

### Step 1: Install Xcode

Install Xcode from the Mac App Store.

### Step 2: Install Rust Targets

```bash
rustup target add aarch64-apple-ios           # Device (arm64)
rustup target add aarch64-apple-ios-sim       # Simulator (Apple Silicon)
rustup target add x86_64-apple-ios            # Simulator (Intel)
```

### Step 3: Build

```bash
cd SoftEtherRust

# For iOS Device (arm64)
cargo build --release --target aarch64-apple-ios --features ios

# For iOS Simulator (Apple Silicon Mac)
cargo build --release --target aarch64-apple-ios-sim --features ios

# For iOS Simulator (Intel Mac)
cargo build --release --target x86_64-apple-ios --features ios
```

### Step 4: Create XCFramework

```bash
./scripts/build-ios.sh
```

---

## Desktop Build

### macOS

```bash
cargo build --release
# Output: target/release/libsoftether.dylib
```

### Linux

```bash
cargo build --release
# Output: target/release/libsoftether.so
```

### Windows

```bash
cargo build --release
# Output: target/release/softether.dll
```

---

## Troubleshooting

### Error: "linker not found"

**Problem:** `linker 'aarch64-linux-android21-clang' not found`

**Solution:** Set the linker environment variable:
```bash
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang"
```

Or add all linkers to your shell profile (see Step 2 above).

---

### Error: "CC compiler not found" (ring crate)

**Problem:** `failed to find tool "aarch64-linux-android-clang"`

**Solution:** Set the CC environment variable:
```bash
export CC_aarch64_linux_android="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang"
```

---

### Error: "No space left on device"

**Problem:** Build fails with temp directory errors.

**Solution:** Use a different temp directory:
```bash
export TMPDIR=/path/to/external/drive/tmp
mkdir -p $TMPDIR
cargo build --release --target armv7-linux-androideabi --features android
```

---

### Error: "ANDROID_NDK_HOME not set"

**Solution:** Set the NDK path:
```bash
# Find your NDK version
ls $ANDROID_HOME/ndk/

# Set it (replace version number)
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/25.1.8937393"
```

---

### UnsatisfiedLinkError on Android

**Problem:** App crashes with `java.lang.UnsatisfiedLinkError: dlopen failed: library "libsoftether.so" not found`

**Solution:** 
1. Check you built for the correct architecture:
   ```bash
   adb shell getprop ro.product.cpu.abi
   ```
2. Verify the .so file exists:
   ```bash
   ls -la app/src/main/jniLibs/*/libsoftether.so
   ```
3. Rebuild and reinstall:
   ```bash
   ./gradlew clean installDebug
   ```

---

### Check NDK Toolchain

Verify toolchain exists:
```bash
ls $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin/*-clang
```

Expected output:
```
.../bin/aarch64-linux-android21-clang
.../bin/armv7a-linux-androideabi21-clang
.../bin/i686-linux-android21-clang
.../bin/x86_64-linux-android21-clang
```

---

## Architecture Reference

| Device Type | ABI | Rust Target | JNI Folder |
|-------------|-----|-------------|------------|
| Modern Android phones | arm64-v8a | aarch64-linux-android | arm64-v8a |
| Older Android phones | armeabi-v7a | armv7-linux-androideabi | armeabi-v7a |
| Android Emulator (Intel) | x86_64 | x86_64-linux-android | x86_64 |
| Old Android Emulator | x86 | i686-linux-android | x86 |
| iOS Device | arm64 | aarch64-apple-ios | - |
| iOS Simulator (M1/M2) | arm64-sim | aarch64-apple-ios-sim | - |
| iOS Simulator (Intel) | x86_64 | x86_64-apple-ios | - |

---

## One-Liner Quick Build

**For your connected device:**
```bash
ARCH=$(adb shell getprop ro.product.cpu.abi) && \
case "$ARCH" in arm64-v8a) T=aarch64-linux-android;; armeabi-v7a) T=armv7-linux-androideabi;; x86_64) T=x86_64-linux-android;; x86) T=i686-linux-android;; esac && \
cargo build --release --target $T --features android && \
mkdir -p ../app/src/main/jniLibs/$ARCH && \
cp target/$T/release/libsoftether.so ../app/src/main/jniLibs/$ARCH/ && \
cd .. && ./gradlew installDebug
```
