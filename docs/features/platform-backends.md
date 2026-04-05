# Feature: Platform Backends

`libzcap` uses one public API and picks the right backend for the current OS.

## Linux

- Native AF_PACKET path.
- Dynamic filter setup is done through socket options.
- Ring buffer mode is used when the kernel supports it.
- Advanced Linux options are available through `zpcap_open_live_ex()` and
  runtime feature checks (`zpcap_detect_features()`).

## macOS / BSD

- Uses `/dev/bpf` to read link-layer frames.
- Run with sufficient permissions or set ACLs for `/dev/bpf*`.

## Windows

- Uses runtime loading of `wpcap.dll`.
- `libzcap` does not require Npcap at build time.
- `zpcap_getevent()` exposes a native event handle for wait-based async loops when the
  backend supports it.

## Migration note

You do not need to change capture code for different platforms when you use the exposed API.
