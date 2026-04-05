# Changelog

All notable changes to libzcap are documented here.

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
