# libzcap Advanced Examples Collection

The explicit goal of `libzcap`'s compatibility architecture is mapping internal Zig capabilities strictly to external cross-compiled API definitions effortlessly. Every example included in this directory can be strictly compiled by `gcc` or `g++` against standard `libc` and `libzcap.so`.

These standalone examples demonstrate 1-to-1 operational conformity with historical drop-ins utilizing `libpcap`.

### Provided Paradigms
- **`01_basic_capture.c`**: Pure C-loop natively hooking an interface cleanly mirroring standard hardware polling mechanisms.
- **`02_pcap_dump.c`**: Direct PCAP stream interception utilizing simple memory pointer wrappers to route network traffic directly securely to the filesystem completely identically to `pcap_dumper_t`.
- **`03_offline_read.cpp`**: Utilizing strong object parsing dynamically from historical traces generated previously by Wireshark/`tcpdump`.
- **`04_bpf_filter.c`**: Dynamically routing a live compiled Berkeley Packet Filter (BPF) expression (`tcp port 80`) structurally pushing physical instruction sizes exactly into the standard Linux network stack dynamically.

### Compiling and Testing
You must have successfully generated `libzcap` locally (via `zig build`) before testing. Execute tests seamlessly from the root output structure mapping headers efficiently:
```bash
# Basic C Linking
gcc -o examples/basic examples/01_basic_capture.c -Iinclude -Lzig-out/lib -lzcap
sudo LD_LIBRARY_PATH=zig-out/lib ./examples/basic

# Advanced C++ Linking
g++ -std=c++11 -o examples/offline examples/03_offline_read.cpp -Iinclude -Lzig-out/lib -lzcap
```
