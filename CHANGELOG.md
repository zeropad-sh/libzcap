# Changelog

All notable changes to libzcap are documented here.

## [0.4.0] - 2026-04-05

### Added
- Added a richer, errno-style error surface for compatibility workflows:
  - `zpcap_geterrnum()`, `zpcap_strerror()`, and `zpcap_perror()` now work with a clearer
    context/error-state model.
  - `zpcap_lib_version()` reports the runtime library compatibility version.
- Added compatibility-layer examples and docs for modern diagnostics:
  - [C99 Error Surface](docs/examples/c99-error-surface.md)
  - [C++11 Error Surface](docs/examples/cpp11-error-surface.md)
  - [C99 Dump Flush](docs/examples/c99-dump-flush.md)
  - [C++11 Dump Flush](docs/examples/cpp11-dump-flush.md)
- Added Linux feature diagnostics coverage for modern/offline fallback behavior:
  - `zpcap_detect_features()` and `zpcap_kernel_version()` now drive runtime behavior and docs/tests.
  - Feature probing now includes `ebpf`, `hw_tstamp`, and `af_xdp` as detected capabilities.
- Added CMake aggregation coverage for additional modern examples:
  - Added `21_error_surface_*` and `22_dump_flush_*` targets to `examples/CMakeLists.txt`.

### Changed
- Updated CI smoke flow to run the new diagnostics and dump examples on all supported platforms.
- Enriched Linux kernel capability docs to include modern feature gates and runtime fallback expectations.
- CI pipeline now captures test and example output to console/log files in a single stream for easier inspection.

### Fixed
- Fixed BPF compiler behavior for unsupported expressions (`ip port 80`, mixed protocols, duplicate
  tokens) to fail deterministically instead of compiling overly-broad programs.
- Fixed several filter instruction encoding/type mismatches in `zpcap` compatibility BPF emission.
- Strengthened offline and dump tests by validating `zpcap_dump_flush()` in CI workflows.
- Improved release note extraction defaults to the new 0.4 surface area.

## [0.3.1] - 2026-04-05

### Added
- Added a dedicated docs page for native async wait workflows:
  - [C++11 Native Event Wait](docs/examples/cpp11-async-native-wait.md)
- Added explicit docs coverage for `zpcap_getevent()` in feature and backend documentation.

### Changed
- Improved documentation discovery by linking native async-wait support from:
  - [docs/README.md](docs/README.md)
  - [docs/getting-started.md](docs/getting-started.md)
  - [docs/features/compatibility-layer.md](docs/features/compatibility-layer.md)
  - [docs/features/advanced-workflows.md](docs/features/advanced-workflows.md)
  - [docs/features/platform-backends.md](docs/features/platform-backends.md)
  - [examples/README.md](examples/README.md)

### Fixed
- Fixed docs/examples parity by documenting one native example that was previously present in code but missing from docs coverage.

## [0.3.0] - 2026-04-05

### Added
- Linux kernel capability discovery APIs for capability-aware startup:
  - `zpcap_detect_features()`
  - `zpcap_kernel_version()`
  - `zpcap_open_live_ex()`
- Runtime configuration surface for Linux performance features:
  - feature-aware capture examples (`examples/20_linux_kernel_features.c`)
  - new docs: [Linux Kernel Capabilities](docs/features/linux-kernel-capabilities.md)
  - richer API docs and feature examples cross-links in docs index/getting started

### Changed
- CI now validates Linux kernel fallback behavior in automated tests (`zig build feature-probe`).
- CI smoke tests now include the Linux kernel feature example in Linux/macOS offline flow.
- Windows E2E workflow now copies discovered DLL artifacts and runs the same C++/C examples set as Linux/macOS where available.
- `linux` backend ring selection now uses clearer fallback behavior for unsupported kernel features.

### Fixed
- Fixed a Windows build break in `src/capture/kernel.zig` where Linux-only `/proc/version` probing was compiled unconditionally.
- Fixed `zpcap_setnonblock` shim error handling behavior to pass `errbuf` safely on all platforms.
- Simplified release compatibility and example output for clearer CI debugging and repeatable diagnostics.

## [0.2.0] - 2026-03-29

### Added
- Changelog-driven GitHub release notes with a dedicated `CHANGELOG.md`.
- Documentation notes for release workflow defaults and CI artifact expectations.
- Linux kernel capability-aware capture controls in `zpcap` compatibility API:
  `zpcap_open_live_ex`, `zpcap_detect_features`, `zpcap_kernel_version`.

### Changed
- Release workflow defaults now use version `0.2.0`.
- Release notes are now generated from `CHANGELOG.md` entries for the released version.

### Fixed
- CI runtime loading for Linux/macOS now sets both `LD_LIBRARY_PATH` and `DYLD_LIBRARY_PATH`.
- Windows E2E workflow now copies available DLL output locations to ensure executable compatibility.
- macOS build now uses signed `BIOCSETF` handling in capture ioctl path.

## [0.1.0] - 2026-03-01

- Initial release of `libzcap`.
