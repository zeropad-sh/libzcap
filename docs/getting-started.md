# Getting Started

## 1. Build libzcap

`libzcap` is built with Zig. You only need a supported Zig toolchain.

```bash
git clone https://github.com/seekaddo/libzcap.git
cd libzcap
zig build
```

For a local sanity check:

```bash
zig build test
```

## 2. Use C headers and link library

Use `include/zpcap.h` and link against `libzcap`.

```bash
# Linux/macOS examples
gcc -std=c99 -Iinclude -Lzig-out/lib -lzcap -o docs/examples/c99-live-capture examples/01_basic_capture.c
```

```bash
# C++11 examples
g++ -std=c++11 -Iinclude -Lzig-out/lib -lzcap -o docs/examples/cpp11-offline-read examples/03_offline_read.cpp
```

## 3. Runtime library path

- **Linux/macOS**
  - Set `LD_LIBRARY_PATH` or `DYLD_LIBRARY_PATH` to `zig-out/lib` for local runs.
- **Windows (MinGW)**
  - Ensure a `zcap.dll` exists in your executable directory or `PATH`.

```bash
export LD_LIBRARY_PATH=zig-out/lib
./your_binary
```

## 4. API naming and migration flow

`libzcap` exposes `zpcap_*` APIs as its C interface.

- Live capture: `zpcap_open_live`, `zpcap_loop`, `zpcap_next`
- Offline replay: `zpcap_open_offline`
- Filters: `zpcap_compile`, `zpcap_setfilter`, `zpcap_freecode`
- Dumping: `zpcap_dump_open`, `zpcap_dump`, `zpcap_dump_close`

## 5. Permissions

- Linux/macOS/BSD capture usually needs elevated permissions for raw device access.
- Windows requires a working Npcap installation and usually administrator permissions.

## 6. Choose a sample

- C99 full samples:
  - [c99-live-capture.md](./examples/c99-live-capture.md)
  - [c99-pcap-dump.md](./examples/c99-pcap-dump.md)
  - [c99-bpf-filter.md](./examples/c99-bpf-filter.md)
  - [c99-next-and-stats.md](./examples/c99-next-and-stats.md)
  - [c99-filtered-file-capture.md](./examples/c99-filtered-file-capture.md)
  - [c99-offline-protocol-stats.md](./examples/c99-offline-protocol-stats.md)
  - [c99-live-options.md](./examples/c99-live-options.md)
- C++11 full sample:
  - [cpp11-offline-read.md](./examples/cpp11-offline-read.md)
  - [cpp11-offline-split.md](./examples/cpp11-offline-split.md)
  - [cpp11-offline-transport-split.md](./examples/cpp11-offline-transport-split.md)

Advanced workflow:
- [Advanced Workflows](./features/advanced-workflows.md)
