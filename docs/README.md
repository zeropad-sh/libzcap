# libzcap Documentation

Welcome to the official libzcap docs.

libzcap is a high-performance packet capture library built in Zig with a
drop-in `zpcap` C ABI for quick migration from `libpcap`.

## What You Can Find Here

- [Getting Started](./getting-started.md): build setup, headers, and first run.
- [C++11 Offline Replay](./examples/cpp11-offline-read.md): complete C++11 example for reading `.pcap` files.
- [C99 Live Capture](./examples/c99-live-capture.md): complete C99 example for live packet capture.
- [C99 PCAP Writer](./examples/c99-pcap-dump.md): complete C99 example for dumping live traffic to disk.
- [C99 BPF Filtering](./examples/c99-bpf-filter.md): complete C99 example for `zpcap_compile` and `zpcap_setfilter`.
- [Zero-Copy Architecture](./features/zero-copy.md): how capture buffers avoid copies.
- [Cross-Platform Backends](./features/platform-backends.md): Linux/macOS/BSD/Windows behavior and prerequisites.
- [`zpcap` Compatibility Layer](./features/compatibility-layer.md): API mapping and migration path.

## Quick Navigation

- If you are trying libzcap for the first time, start with [Getting Started](./getting-started.md).
- If you need a full sample in C99, open:
  - [Live Capture](./examples/c99-live-capture.md)
  - [PCAP Writer](./examples/c99-pcap-dump.md)
  - [BPF Filter](./examples/c99-bpf-filter.md)
- If you need a full sample in C++11, open:
  - [Offline PCAP Reader](./examples/cpp11-offline-read.md)
