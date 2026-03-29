# Getting Started

## 1. Install libzcap

Pick one path:

- **From source (requires Zig `0.15.2+`)**
  - Build your own binaries with `zig build`:
    ```bash
    git clone https://github.com/seekaddo/libzcap.git
    cd libzcap
    zig build
    ```
  - Optional quick check:
    ```bash
    zig build test
    ```

- **From prebuilt archives (no Zig required)**
  - Go to the [GitHub Releases page](https://github.com/seekaddo/libzcap/releases).
  - Download the archive matching your OS/arch, for example:
    - `libzcap-vX.Y.Z-linux-x86_64.tar.gz`
    - `libzcap-vX.Y.Z-windows-x86_64.tar.gz`
    - `libzcap-vX.Y.Z-macos-aarch64.tar.gz`
  - Extract it before running examples:
    ```bash
    tar -xzf libzcap-vX.Y.Z-linux-x86_64.tar.gz
    ```

For source builds, outputs are placed in `zig-out/lib` and headers under `zig-out/include`.  
For prebuilt archives, use the unpacked `include/` and library files directly from the tarball.

## 2. Use C headers and link library

Use `zpcap.h` from your build output.

```bash
# If you built from source:
# Linux/macOS examples
gcc -std=c99 -Iinclude -Lzig-out/lib -lzcap -o docs/examples/c99-live-capture examples/01_basic_capture.c
```

```bash
# C++11 examples
g++ -std=c++11 -Iinclude -Lzig-out/lib -lzcap -o docs/examples/cpp11-offline-read examples/03_offline_read.cpp
```

If you used a prebuilt archive, replace:
- `-Iinclude` with `-I/path/to/extracted/include`
- `-Lzig-out/lib` with `-L/path/to/extracted/<platform-folder>`

## 3. Runtime library path

- **Linux/macOS**
  - For source builds, set `LD_LIBRARY_PATH` or `DYLD_LIBRARY_PATH` to `zig-out/lib`.
  - For prebuilt archives, set it to the extracted library directory.
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
