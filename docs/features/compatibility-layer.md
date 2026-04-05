# Feature: C API Compatibility Layer

`libzcap` exposes `zpcap_*` symbols through a small compatibility layer.

## What this enables

- Existing `libpcap` code can move with minimal edits.
- Typical migration steps:
  - `#include <pcap.h>` -> `#include <zpcap.h>` (or keep your existing include style)
  - `pcap_` symbol prefix → `zpcap_` symbol prefix

## Supported operations in this layer

- Open live/offline capture
- Enumerate capture devices and resolve default device
- Packet send and sendpacket
- Non-blocking read mode (`zpcap_setnonblock`/`zpcap_getnonblock`)
- FD-based async integration (`zpcap_get_selectable_fd`) for event loops on supported platforms
- Native event handle integration (`zpcap_getevent`) where the backend exposes one
- Per-handle stats (`zpcap_stats`)
- Loop callback processing
- BPF compile/apply/free
- Dumper open/dump/close
- Optional feature-aware open path on Linux (`zpcap_open_live_ex`)
- Runtime feature probes (`zpcap_detect_features`, `zpcap_kernel_version`)

## Current compatibility envelope

`zpcap_*` currently covers the common migration points used by CLI tools and packet utilities.
It does not yet expose every legacy `pcap_*` symbol. Notable gaps are:
- Interface-specific metadata (addresses, descriptions and status flags are returned where available, but not all legacy fields are parsed).
  - Advanced legacy helpers such as `pcap_set_datalink`, `pcap_getnonblock` variants and link-layer helpers.

`libzcap.h` is intentionally separate and provides the newer native API for projects that do not need strict `libpcap` symbol parity.

## Why this exists

- It keeps legacy C/C++ users productive.
- It keeps migration work small.
- It keeps existing test paths stable while native Zig APIs grow.
