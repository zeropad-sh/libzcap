# C++11 Example: Offline Split and Repack

This example reads an offline pcap and writes only IPv4 packets to a new file.

## Source (`examples/07_offline_split_ipv4.cpp`)

```cpp
#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <zpcap.h>

struct split_context_t {
    zpcap_dumper_t *dumper;
    int total;
    int ipv4_only;
};

static bool is_ipv4_ethernet(const uint8_t *pkt, uint32_t caplen) {
    if (caplen < 14) return false;
    const uint16_t ether_type = (uint16_t(pkt[12]) << 8) | uint16_t(pkt[13]);
    return ether_type == 0x0800;
}

static void packet_handler(uint8_t *user, const zpcap_pkthdr *hdr, const uint8_t *packet) {
    auto *ctx = reinterpret_cast<split_context_t *>(user);
    if (!ctx || !hdr || !packet) return;

    ctx->total++;
    if (is_ipv4_ethernet(packet, hdr->caplen)) {
        ctx->ipv4_only++;
        if (ctx->dumper) {
            zpcap_dump((uint8_t *)ctx->dumper, hdr, packet);
        }
    }
}

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *input = (argc > 1) ? argv[1] : "output_c_test.pcap";

    zpcap_t *handle = zpcap_open_offline(input, errbuf);
    if (handle == nullptr) {
        std::cerr << "Failed to open offline input: " << errbuf << "\n";
        return 1;
    }

    zpcap_dumper_t *dumper = zpcap_dump_open(handle, "ipv4_only.pcap");
    if (dumper == nullptr) {
        std::cerr << "Failed to create ipv4_only.pcap\n";
        zpcap_close(handle);
        return 1;
    }

    split_context_t ctx{dumper, 0, 0};
    zpcap_loop(handle, -1, packet_handler, reinterpret_cast<uint8_t *>(&ctx));
    zpcap_dump_close(dumper);
    zpcap_close(handle);

    std::cout << "Input packets: " << ctx.total << "\n";
    std::cout << "IPv4 packets: " << ctx.ipv4_only << "\n";
    std::cout << "Saved output to ipv4_only.pcap\n";
    return 0;
}
```

## Build and run

```bash
zig build
g++ -std=c++11 -o docs/examples/cpp11-offline-split examples/07_offline_split_ipv4.cpp -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/cpp11-offline-split examples/input.pcap
```

## What this shows

- Offline capture pipeline with callback reuse.
- In-callback protocol filtering (IPv4 detection from Ethernet header).
- Repacking selected packets into a new pcap file.
