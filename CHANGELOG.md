# Changelog

All notable changes to libzcap are documented here.

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
