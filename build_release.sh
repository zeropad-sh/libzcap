#!/bin/bash
# libzcap Release Builder — builds static libraries and the zigdump CLI for all platforms.
# Usage: ./build_release.sh [version] [platform]
# Platforms: all (default), linux, windows, mac
#
# Examples:
#   ./build_release.sh              # build all platforms
#   ./build_release.sh 0.1.0 linux  # build only linux
#
# Outputs to ./releases/ with tars named like libzcap-v0.1.0-x86_64-linux.tar.gz

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

PROJECT_NAME="libzcap"
DEFAULT_VERSION="0.1.0"
VERSION=${1:-$DEFAULT_VERSION}
PLATFORM=${2:-all}
RELEASE_DIR="releases"
ZIG="zig"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/${PROJECT_NAME}-release.XXXXXX")
GLOBAL_CACHE_DIR="$WORK_DIR/global-cache"

cleanup() {
    rm -rf "$WORK_DIR"
}

trap cleanup EXIT

# Target triples
declare -A LINUX_TARGETS=(
    ["linux-x86_64"]="x86_64-linux-gnu"
    ["linux-i386"]="x86-linux-musl"
    ["linux-aarch64"]="aarch64-linux-gnu"
)

declare -A WINDOWS_TARGETS=(
    ["windows-x86_64"]="x86_64-windows-gnu"
    ["windows-i386"]="x86-windows-gnu"
)

declare -A MACOS_TARGETS=(
    ["macos-aarch64"]="aarch64-macos-none"
)

# Select targets
declare -A TARGETS=()
case "$PLATFORM" in
    all)
        for k in "${!LINUX_TARGETS[@]}"; do TARGETS[$k]=${LINUX_TARGETS[$k]}; done
        for k in "${!WINDOWS_TARGETS[@]}"; do TARGETS[$k]=${WINDOWS_TARGETS[$k]}; done
        for k in "${!MACOS_TARGETS[@]}"; do TARGETS[$k]=${MACOS_TARGETS[$k]}; done
        ;;
    linux)
        for k in "${!LINUX_TARGETS[@]}"; do TARGETS[$k]=${LINUX_TARGETS[$k]}; done
        ;;
    windows)
        for k in "${!WINDOWS_TARGETS[@]}"; do TARGETS[$k]=${WINDOWS_TARGETS[$k]}; done
        ;;
    mac)
        for k in "${!MACOS_TARGETS[@]}"; do TARGETS[$k]=${MACOS_TARGETS[$k]}; done
        ;;
    *)
        echo "Unknown platform: $PLATFORM"
        echo "Usage: $0 [version] [platform]"
        echo "Platforms: all, linux, windows, mac"
        exit 1
        ;;
esac

rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

build_for_target() {
    local plat_arch="$1"
    local triple="$2"
    local prefix_dir="$WORK_DIR/$plat_arch/prefix"
    local cache_dir="$WORK_DIR/$plat_arch/cache"

    echo "Building $PROJECT_NAME for $triple (ReleaseFast)..."

    # NOTE: Since currently libzcap is tightly coupled to Linux AF_PACKET in handle.zig,
    # cross-compiling for windows/macos might fail at the Zig compilation stage unless 
    # those backends are implemented or dummied out.
    if ! "$ZIG" build \
        -Doptimize=ReleaseFast \
        -Dtarget="$triple" \
        --prefix "$prefix_dir" \
        --cache-dir "$cache_dir" \
        --global-cache-dir "$GLOBAL_CACHE_DIR"; then
        echo "Build failed/skipped for $triple"
        return 1
    fi

    local plat_dir
    plat_dir=$(echo "$plat_arch" | cut -d'-' -f1)
    local out_dir="$RELEASE_DIR/$plat_dir/$plat_arch"
    mkdir -p "$out_dir"

    # Copy bin and shared library explicit output
    if [ -d "$prefix_dir/bin" ]; then
        cp -PR "$prefix_dir/bin"/* "$out_dir/" 2>/dev/null || true
    fi
    if [ -d "$prefix_dir/lib" ]; then
        cp -PR "$prefix_dir/lib"/*.so* "$out_dir/" 2>/dev/null || true
        cp -PR "$prefix_dir/lib"/*.dylib "$out_dir/" 2>/dev/null || true
        cp -PR "$prefix_dir/lib"/*.dll* "$out_dir/" 2>/dev/null || true
    fi
    
    # Copy headers just in case it exports any
    if [ -d "$prefix_dir/include" ]; then
        cp -R "$prefix_dir/include" "$out_dir/"
    fi

    # Package
    (cd "$RELEASE_DIR" && tar -czf "${PROJECT_NAME}-v${VERSION}-${plat_arch}.tar.gz" "$plat_dir/$plat_arch")

    echo "Built: ${PROJECT_NAME}-v${VERSION}-${plat_arch}.tar.gz"
}

FAILED_TARGETS=()

for plat_arch in "${!TARGETS[@]}"; do
    if ! build_for_target "$plat_arch" "${TARGETS[$plat_arch]}"; then
        FAILED_TARGETS+=("$plat_arch")
    fi
done

echo ""
if (( ${#FAILED_TARGETS[@]} > 0 )); then
    echo "Release build completed with failures: ${FAILED_TARGETS[*]}"
    echo "Note: Windows and macOS builds will fail until their respective capture backends are implemented."
    exit 1
fi

echo "All releases built in $RELEASE_DIR!"
ls -la "$RELEASE_DIR"/*.tar.gz 2>/dev/null || echo "(no tar files found)"
