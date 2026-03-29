# Feature: Zero-Copy and Low Latency

`libzcap` avoids extra packet memory copies whenever the platform can support it.

## Linux

- Uses Linux socket packet capture with memory-mapped ring buffers (`TPACKET_V3`) when available.
- Packet payload pointers are passed directly to callbacks from the ring buffer.
- This keeps per-packet allocations at zero for hot paths.

## macOS and BSD

- Uses `/dev/bpf` backends and reads packet data from kernel-provided buffers.
- Callback payload pointers reference the current kernel read buffer for that cycle.

## Windows

- Uses Npcap-backed capture paths when available on the system.

## Practical note

`libzcap` still supports a `copy` path on some backends. In that mode packet data is still reused by libzcap, so callers must treat packet pointers as valid only during callback/poll scope.

## What this improves

- Lower CPU use during long capture runs.
- Less memory allocator activity.
- More stable performance under load.
