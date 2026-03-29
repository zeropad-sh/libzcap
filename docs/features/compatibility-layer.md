# Feature: C API Compatibility Layer

`libzcap` exposes `zpcap_*` symbols through a small compatibility layer.

## What this enables

- Existing `libpcap` code can move with minimal edits.
- Typical migration steps:
  - `#include <pcap.h>` -> `#include <zpcap.h>` (or keep your existing include style)
  - `pcap_` symbol prefix → `zpcap_` symbol prefix

## Supported operations in this layer

- Open live/offline capture
- Loop callback processing
- BPF compile/apply/free
- Dumper open/dump/close

## Why this exists

- It keeps legacy C/C++ users productive.
- It keeps migration work small.
- It keeps existing test paths stable while native Zig APIs grow.
