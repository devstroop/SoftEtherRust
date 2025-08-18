#!/usr/bin/env bash
set -euo pipefail

# Verifies the expected slices and headers exist in the packaged XCFramework used by the iOS app.
# This helps CI fail fast if a slice goes missing after history rewrites or packaging changes.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XCFRAMEWORK_DIR="$ROOT_DIR/../WorxVPN-iOS/RustFramework/SoftEtherClient.xcframework"

echo "[verify_xcframework] Checking: $XCFRAMEWORK_DIR"

if [[ ! -d "$XCFRAMEWORK_DIR" ]]; then
  echo "ERROR: XCFramework directory not found: $XCFRAMEWORK_DIR" >&2
  exit 1
fi

REQS=(
  "ios-arm64/libsoftether_ffi.a"
  "ios-arm64-simulator/libsoftether_ffi_sim.a"
)

missing=0
for rel in "${REQS[@]}"; do
  path="$XCFRAMEWORK_DIR/$rel"
  if [[ ! -e "$path" ]]; then
    echo "ERROR: Missing XCFramework component: $rel" >&2
    missing=1
  else
    echo "OK: $rel"
  fi
done

if [[ "$missing" != 0 ]]; then
  echo "XCFramework verification failed." >&2
  exit 2
fi

# Detect whether headers are packaged as a directory with softether_ffi.h or a single file named 'Headers'
check_header_slice() {
  local slice_dir="$1"
  local dir_path="$XCFRAMEWORK_DIR/$slice_dir/Headers"
  if [[ -d "$dir_path" ]]; then
    if [[ ! -f "$dir_path/softether_ffi.h" ]]; then
      echo "ERROR: $slice_dir headers directory present but softether_ffi.h missing." >&2
      return 1
    fi
    if ! grep -Rqs "int[[:space:]]\+softether_client_get_mac" "$dir_path/softether_ffi.h"; then
      echo "ERROR: softether_client_get_mac declaration not found in $slice_dir headers." >&2
      return 1
    fi
    echo "OK: $slice_dir headers directory with softether_ffi.h"
    return 0
  elif [[ -f "$dir_path" ]]; then
    # Some packaging formats use a single header file named 'Headers'
    if ! grep -Rqs "int[[:space:]]\+softether_client_get_mac" "$dir_path"; then
      echo "ERROR: softether_client_get_mac declaration not found in $slice_dir/Headers file." >&2
      return 1
    fi
    echo "OK: $slice_dir single header file 'Headers'"
    return 0
  else
    echo "ERROR: $slice_dir Headers not found (neither file nor directory)." >&2
    return 1
  fi
}

check_header_slice ios-arm64 || exit 3
check_header_slice ios-arm64-simulator || exit 4

echo "[verify_xcframework] All checks passed."
