# libzcap Advanced Examples Collection

The explicit goal of `libzcap`'s compatibility architecture is mapping internal Zig capabilities strictly to external cross-compiled API definitions effortlessly. Every example included in this directory can be compiled against standard `libc` and `libzcap`.

These standalone examples demonstrate 1-to-1 operational conformity with historical drop-ins utilizing `libpcap`.

### Provided Paradigms
- **`01_basic_capture.c`**: Pure C-loop natively hooking an interface cleanly mirroring standard hardware polling mechanisms.
- **`02_pcap_dump.c`**: Direct PCAP stream interception utilizing simple memory pointer wrappers to route network traffic directly securely to the filesystem completely identically to `pcap_dumper_t`.
- **`03_offline_read.cpp`**: Utilizing strong object parsing dynamically from historical traces generated previously by Wireshark/`tcpdump`.
- **`04_bpf_filter.c`**: Dynamically routing a live compiled Berkeley Packet Filter (BPF) expression (`tcp port 80`) structurally pushing physical instruction sizes exactly into the standard Linux network stack dynamically.
- **`05_next_and_stats.c`**: Pull-based packet reads with `zpcap_next` and simple in-app counters.
- **`06_filtered_capture_to_file.c`**: End-to-end live filtering plus pcap file output in one run.
- **`07_offline_split_ipv4.cpp`**: Offline IPv4 packet splitter that writes only IPv4 frames to a new capture file.
- **`08_offline_protocol_stats.c`**: Offline Ethernet frame type counter with zero-copy callback-based stats.
- **`09_offline_split_transport.cpp`**: Offline dual-output splitter for TCP vs UDP packets.
- **`10_live_capture_options.c`**: Live capture with configurable device/filter/count/dump target.
- **`11_findalldevs_lookupdev.c`**: Enumerate local capture devices and resolve the default interface.
- **`12_nonblocking_stats.c`**: Non-blocking mode, `zpcap_next_ex`, and stats with offline input.
- **`13_send_packet.c`**: Packet injection using `zpcap_sendpacket` and `zpcap_send`.
- **`15_findalldevs_lookupdev.cpp`**: C++ version of interface enumeration and default selection.
- **`16_nonblocking_stats.cpp`**: C++ non-blocking loop and stats with `zpcap_next_ex`.
- **`17_send_packet.cpp`**: C++ packet injection with `zpcap_sendpacket` and `zpcap_send`.
- **`18_async_select.c`**: C event-loop capture using `select()` and `zpcap_next_ex`.
- **`18_async_select.cpp`**: C++ event-loop capture using `select()` and `zpcap_next_ex`.
- **`19_async_native_wait.cpp`**: Cross-platform async event example that uses selectable FD,
  native event handles when available, and timed-poll fallback on either path.
- **`20_linux_kernel_features.c`**: Linux feature probe and feature-aware open path for `ring_mmap`, fanout, and busy-poll with privilege-safe fallback.
- **`21_error_surface.c` / `21_error_surface.cpp`**: Diagnostics and error-surface example using
  `zpcap_lib_version`, `zpcap_strerror`, `zpcap_perror`, and `zpcap_dispatch`.
- **`22_dump_flush.c` / `22_dump_flush.cpp`**: Offline durability example using
  `zpcap_dump_flush` periodically and at shutdown.

### Compiling and Testing
You must have successfully generated `libzcap` locally (via `zig build`) before testing.

Optional: use one CMake command to build all examples at once:
```bash
cmake -S examples -B examples/build -DLIBZCAP_ROOT="$(pwd)" -DLIBZCAP_BUILD_DIR="$(pwd)/zig-out"
cmake --build examples/build -j
```

From repository root, you can run a single helper script:
```bash
./build_examples.sh
```

If you do not want to use CMake, you can still compile a single file with `gcc`/`g++`:
```bash
# Basic C Linking
gcc -o examples/basic examples/01_basic_capture.c -Iinclude -Lzig-out/lib -lzcap
sudo LD_LIBRARY_PATH=zig-out/lib ./examples/basic

# Advanced C++ Linking
g++ -std=c++11 -o examples/offline examples/03_offline_read.cpp -Iinclude -Lzig-out/lib -lzcap
```

> For Windows users, prefer the CMake flow above because `-lzcap` may not
> resolve depending on your local Mingw/Visual Studio/ABI pairing.

All docs and copy-paste examples now live under [docs/](../docs/README.md).
