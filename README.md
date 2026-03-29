<p align="center">
  <img src="logo.png" alt="libzcap logo" width="300">
</p>

# ⚡ libzcap (zpcap)

**Zero-copy, high-performance, cross-platform packet capture library written entirely in Zig.**

`libzcap` is a modern, dependency-free alternative to `libpcap`. Engineered explicitly for bleeding-edge throughput and simplicity, it implements OS kernel networking primitives natively and entirely in Zig. 

Whether you are building high-speed network analyzers, intrusion detection systems, or custom protocol dissectors, `libzcap` provides a universally native, memory-safe, and instantly portable foundation.

## 🚀 Key Features

*   **Zero-Copy Hardware Accerlation**: Bypasses context switching latency natively on Unix implementations.
    *   *Linux*: Leverages `AF_PACKET` with memory-mapped `TPACKET_V3` ring buffers.
    *   *macOS/BSD*: Natively binds and memory-maps `/dev/bpf` character devices.
    *   *Windows*: Dynamically binds the Npcap `wpcap.dll` runtime without static dependencies whatsoever.
*   **True Zero-Dependency**: `libzcap` compiles into a tiny, standalone library. There is absolutely no hidden `libpcap` static linkage required across any operating system.
*   **`zpcap` C-ABI Compatibility**: Provides a drop-in `<zpcap.h>` interface. Migrate legacy C/C++ `libpcap` applications instantly by strictly renaming `pcap_` functions to `zpcap_`. Safe, ABI-stable, and entirely namespace-isolated to explicitly prevent symbol collisions!
*   **Robust Protocol Dissection**: Hardened, heavily saturation-tested protocol traversers natively tracking metrics on truncated or malformed traffic natively:
    *   **Data Link**: Ethernet, IEEE 802.11 (Wi-Fi), Radiotap, VLAN, NULL/Loopback
    *   **Network**: IPv4, IPv6, ARP
    *   **Transport**: TCP, UDP, SCTP, ICMP, ICMPv6
*   **Thread-Safe Metrics**: Atomic lock-free `packets`, `bytes`, and `drops` hardware reception counters.
*   **Fully Documented API**: Doxygen-styled C/C++ header integrations natively documenting robust networking flags.
*   **Cross-Platform Builds**: Provided scripts compile `libzcap` structurally producing `.so`, `.dylib`, and `.dll` alongside C-Headers instantly locally.

## 🛠️ Build & Installation

`libzcap` is built natively utilizing [Zig 0.15.2+](https://ziglang.org/).

```bash
# Clone the repository
git clone https://github.com/seekaddo/libzcap.git
cd libzcap

# Build and run the rigorous zero-copy protocol test suite
zig build test
```

## 📚 Documentation

Use the docs folder for a guided, example-first entry point:

- [Documentation Hub](docs/README.md)
- [Getting Started](docs/getting-started.md)

## 🖥️ zigdump CLI Usage

The repository includes a natively built testing harness named `zigdump` acting as a comprehensive, fully-featured pcap generation and packet extraction command line tool natively exercising libzcap!

```bash
# Capture 100 packets locally producing metrics directly over AF_PACKET/NPF
./zig-out/bin/zigdump --capture eth0 output.pcap 100

# Traverse standard PCAP blocks decoding hardware streams
./zig-out/bin/zigdump output.pcap
```

## ⚖️ Why use `libzcap`?

Even for developers strictly utilizing pure C or C++, `libzcap` offers massive structural and architectural advantages when linked dynamically or consumed via the drop-in `zpcap.h` interface:

*   **Microservice & Embedded Friendly**: We do not compile tens of thousands of lines of legacy UNIX/Solaris fallback systems or internal BPF compiler engines. The resulting binary footprint is incredibly tiny—perfect for IoT devices, routers, or slim system containers.
*   **No Windows SDK "Dependency Hell"**: Building C/C++ projects against standard `libpcap` on Windows usually means configuring CMake to natively link massive proprietary `Npcap SDK` static `.lib` files. `libzcap` solves this by binding the Npcap engine transparently at runtime.
*   **CI/CD Pipeline Friction**: Compiling standard `libpcap` from source typically requires `make`, `autoconf`, `flex`, `bison`, and `m4` installed on the runner host. The only tool necessary to perfectly reproduce `libzcap` internally across any OS is the base Zig compiler.
*   **Thread-Safe Performance Metrics**: Standard `libpcap`'s `pcap_stats()` design inherently struggles natively during high-performance concurrent polling. `libzcap` aggressively utilizes hard Atomic architectures (lock-free `.release`/`.acquire` boundaries) guaranteeing completely thread-safe hardware polling metrics.

### 💻 Drop-in C/C++ Example

Migrating legacy applications to `libzcap` is as simple as renaming `pcap_` configurations to `zpcap_` and including our generic header! No complex build scripts required.

```c
#include <stdio.h>
#include <stdint.h>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *pkthdr, const uint8_t *packet) {
    printf("Captured packet with length: %d\n", pkthdr->len);
    
    // Explicitly write the zero-copy packet directly to the dynamically generated .pcap file
    if (user != NULL) {
        zpcap_dump(user, pkthdr, packet);
    }
}

int main() {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    
    // Natively bind to AF_PACKET, BPF, or Npcap completely bypassing libpcap!
    zpcap_t *handle = zpcap_open_live("eth0", 65535, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Failed to open network interface: %s\n", errbuf);
        return 1;
    }
    
    // Natively open a PCAP dumper matching standard C-ABI libpcap designs!
    zpcap_dumper_t *dumper = zpcap_dump_open(handle, "output_c_test.pcap");
    
    // Start the zero-copy processing loop, passing the dumper natively as the `user` context!
    zpcap_loop(handle, 10, packet_handler, (uint8_t*)dumper);
    
    zpcap_dump_close(dumper);
    zpcap_close(handle);
    
    return 0;
}
```
