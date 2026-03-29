# Feature: Platform Backends

`libzcap` uses one public API and picks the right backend for the current OS.

## Linux

- Native AF_PACKET path.
- Dynamic filter setup is done through socket options.
- Ring buffer mode is used when the kernel supports it.

## macOS / BSD

- Uses `/dev/bpf` to read link-layer frames.
- Run with sufficient permissions or set ACLs for `/dev/bpf*`.

## Windows

- Uses runtime loading of `wpcap.dll`.
- `libzcap` does not require Npcap at build time.

## Migration note

You do not need to change capture code for different platforms when you use the exposed API.
