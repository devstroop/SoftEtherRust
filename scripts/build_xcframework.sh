#!/usr/bin/env bash
set -euo pipefail

# Build the softether_ffi static library for iOS device and simulators, then produce an XCFramework.
# Requires Rust targets installed: aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios.
# Usage: ./scripts/build_xcframework.sh [--release] [--copy-to /absolute/path]
PROFILE=debug
if [[ ${1:-} == "--release" ]]; then PROFILE=release; fi
if [[ ${1:-} == "-r" ]]; then PROFILE=release; fi
if [[ ${1:-} == "release" ]]; then PROFILE=release; fi
if [[ ${1:-} == "debug" ]]; then PROFILE=debug; fi
if [[ ${1:-} == "-d" ]]; then PROFILE=debug; fi
if [[ ${1:-} == "--debug" ]]; then PROFILE=debug; fi
BUILD_DIR="$PROFILE"
if [[ "$PROFILE" == "release" ]]; then CARGO_FLAGS=(--release); else CARGO_FLAGS=(); fi

# Parse optional args
COPY_TO=""
for ((i=1; i<=$#; i++)); do
  arg="${!i}"
  if [[ "$arg" == "--copy-to" ]]; then
    j=$((i+1))
    if [[ $j -le $# ]]; then
      COPY_TO="${!j}"
    fi
  fi
done

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
HEADER="$ROOT_DIR/crates/ffi/include/softether_ffi.h"
OUT_DIR="$ROOT_DIR/target/xcframework"
mkdir -p "$OUT_DIR"

# Ensure targets exist (best-effort)
for T in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  if ! rustup target list --installed | grep -q "^$T$"; then
    echo "Rust target $T not installed. Install with: rustup target add $T" >&2
  fi
done

# Build static libs (use explicit manifest-path so script works from any CWD)
# Use safe expansion for arrays under 'set -u'
SAFE_FLAGS_DEV=${CARGO_FLAGS[@]:-}
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --target aarch64-apple-ios ${SAFE_FLAGS_DEV} -p softether_ffi
SAFE_FLAGS_SIM=${CARGO_FLAGS[@]:-}
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --target aarch64-apple-ios-sim ${SAFE_FLAGS_SIM} -p softether_ffi
SAFE_FLAGS_X86=${CARGO_FLAGS[@]:-}
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --target x86_64-apple-ios ${SAFE_FLAGS_X86} -p softether_ffi

# Paths
LIB_DEV="$ROOT_DIR/target/aarch64-apple-ios/$BUILD_DIR/libsoftether_ffi.a"
LIB_SIM_ARM64="$ROOT_DIR/target/aarch64-apple-ios-sim/$BUILD_DIR/libsoftether_ffi.a"
LIB_SIM_X86="$ROOT_DIR/target/x86_64-apple-ios/$BUILD_DIR/libsoftether_ffi.a"

# Create a universal simulator lib
LIPO_SIM="$OUT_DIR/libsoftether_ffi_sim.a"
rm -f "$LIPO_SIM"
lipo -create "$LIB_SIM_ARM64" "$LIB_SIM_X86" -output "$LIPO_SIM"

# Create the XCFramework
XC_OUT="$OUT_DIR/SoftEtherClient.xcframework"
rm -rf "$XC_OUT"
xcodebuild -create-xcframework \
  -library "$LIB_DEV" -headers "$HEADER" \
  -library "$LIPO_SIM" -headers "$HEADER" \
  -output "$XC_OUT"

echo "XCFramework created at: $XC_OUT"

# Optionally copy xcframework to an external destination (e.g., WorxVPN-iOS/RustFramework)
if [[ -n "$COPY_TO" ]]; then
  DEST="$COPY_TO"
  if [[ ! "$DEST" =~ \.xcframework$ ]]; then
    mkdir -p "$DEST"
    DEST="$DEST/SoftEtherClient.xcframework"
  else
    mkdir -p "$(dirname "$DEST")"
  fi
  rm -rf "$DEST"
  cp -R "$XC_OUT" "$DEST"
  echo "Copied XCFramework to: $DEST"
fi
