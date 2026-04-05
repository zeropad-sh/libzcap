# Advanced Capture Workflows

This page covers the higher-value patterns you can use with current `zpcap` APIs.

## 1) Pull model with live counters

If you need more control than callback loop, use `zpcap_next`.

- Read packet-by-packet in a `while` loop.
- Increment counters in your app.
- Decide when to stop based on custom logic.

See: [C99 Pull API + Stats](../examples/c99-next-and-stats.md)

## 2) Filter then dump in one pass

`zpcap_compile` + `zpcap_setfilter` can run first, then `zpcap_loop` handles data only.

- Keeps filter logic close to kernel/device filtering path.
- You can dump only matching packets in callback through the same context pointer.

See: [C99 Filtered Capture to PCAP](../examples/c99-filtered-file-capture.md)

## 3) Offline repacking

For PCAP cleanup and splitting, combine:

- `zpcap_open_offline` for input.
- `zpcap_dump_open` for output.
- Filter logic in callback (for protocol-aware extraction).

See: [C++11 Offline Split](../examples/cpp11-offline-split.md)

## 4) Offline protocol analytics

For high-volume analysis you can classify packets in the callback without copying packet payload.

- Use one offline pass and keep counters in a user context.
- Emit separate output files or reports for protocol mixes.

See: [C99 Offline Protocol Stats](../examples/c99-offline-protocol-stats.md)

## 5) Production-style live capture knobs

Real tools often need one binary with runtime options: device, filter expression, packet limit, and output path.

- Configure once at startup (`zpcap_compile` + `zpcap_setfilter`).
- Keep counters and the dumper pointer in callback context.
- Close handles in a deterministic cleanup path.

See: [C99 Live Capture Options](../examples/c99-live-options.md)

## 6) Keep expectations clear

- Current C API is compact and stability-focused.
- `zpcap_setfilter` is supported for live captures.
- Offline code currently uses callback-level filtering because live-kernel filter attachment is not available for offline handles in this API surface.
- Use async read loops by combining `zpcap_get_selectable_fd` + `zpcap_setnonblock` + `zpcap_next_ex`.
  See:
  - [C99 Async Select Loop](../examples/c99-async-select.md)
  - [C++11 Async Select Loop](../examples/cpp11-async-select.md)

For Windows-native flow, you can also combine `zpcap_getevent` with
`WaitForSingleObject` and keep the same loop logic.

- [C++11 Native Event Wait](../examples/cpp11-async-native-wait.md)

## 7) Linux feature-aware runtime selection

Use `zpcap_detect_features()` and `zpcap_open_live_ex()` when you want a single
binary that adapts automatically:

- detect `TPACKET_V3`, fanout, and busy-poll support before opening
- request `ring_mmap` first, with controlled fallback to copy mode for older kernels
- keep one startup path for Linux and no-op on unsupported kernels

See:
- [C99 Linux Kernel Features](../examples/c99-linux-kernel-features.md)
