#!/usr/bin/env bash
# Build all libzcap examples in one CMake invocation.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT_DIR}/zig-out/lib"
EXAMPLES_BUILD_DIR="${ROOT_DIR}/examples/build"
JOBS="${CMAKE_BUILD_PARALLEL_LEVEL:-}"

if ! command -v cmake >/dev/null 2>&1; then
    echo "Error: cmake is required for this script."
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: build artifacts not found in $BUILD_DIR."
    echo "Run 'zig build' first, or set a custom build dir by editing BUILD_DIR in this script."
    exit 1
fi

if ! compgen -G "$BUILD_DIR"/libzcap* >/dev/null 2>&1; then
    echo "Error: no libzcap artifact was found under $BUILD_DIR."
    echo "Run 'zig build' first, or set a custom build dir by editing BUILD_DIR in this script."
    exit 1
fi

cmake \
  -S "${ROOT_DIR}/examples" \
  -B "$EXAMPLES_BUILD_DIR" \
  -DLIBZCAP_ROOT="$ROOT_DIR" \
  -DLIBZCAP_BUILD_DIR="$BUILD_DIR"

if [ -n "$JOBS" ]; then
    cmake --build "$EXAMPLES_BUILD_DIR" -j "$JOBS"
else
    cmake --build "$EXAMPLES_BUILD_DIR"
fi
