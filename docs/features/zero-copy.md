# Feature: Zero-Copy and Low Latency

`libzcap` avoids extra packet memory copies whenever the platform can support it.

## Linux

- Uses Linux socket packet capture with memory-mapped ring buffers (`TPACKET_V3`) when available.
- Packet payload pointers are passed directly to callbacks from the ring buffer.

## macOS and BSD

- Uses `/dev/bpf` backends and reads packet data from kernel-provided buffers.

## Windows

- Uses Npcap-backed capture paths when available on the system.

## What this improves

- Lower CPU use during long capture runs.
- Less memory allocator activity.
- More stable performance under load.
