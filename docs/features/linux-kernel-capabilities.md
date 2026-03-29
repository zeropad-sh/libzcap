# Linux Kernel Capabilities

`libzcap` uses Linux `AF_PACKET` features only when they exist in the host kernel:

- `TPACKET_V3` (`ring_mmap`) for zero-copy ring capture
- `PACKET_FANOUT` for split receive fanout
- `SO_BUSY_POLL` for low-latency polling

`libzcap` exposes these capabilities through `zpcap_detect_features()` and applies them through `zpcap_open_live_ex()`.

## Version gates

| Feature | Kernel floor | Source |
| --- | --- | --- |
| `ring_mmap` | 3.2.0 | `TPACKET_V3` |
| `fanout` | 2.6.37 | `PACKET_FANOUT` |
| `busy_poll` | 3.11.0 | `SO_BUSY_POLL` |

## Fallback behavior

- If `ring_mmap` is not available, `libzcap` uses copy mode automatically when
  `fallback_to_copy` is enabled.
- Fanout and busy-poll options are rejected if the kernel does not support them.
- `zpcap_open_live` keeps existing behavior and requests ring mode by default for
  best throughput.
- `zpcap_open_live_ex` lets you control that behavior explicitly.

## Runtime checks in C

- Call `zpcap_detect_features()` before opening.
- Optionally call `zpcap_kernel_version()` for diagnostics.
- Use `zpcap_open_options` to request ring/fanout/busy-poll and fallback settings.

## Example

- [C99: Linux kernel feature-aware capture](../examples/c99-linux-kernel-features.md)
