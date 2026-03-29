# C++11 Example: Split TCP/UDP Offline

This example reads one offline capture and writes TCP frames to `tcp_only.pcap`
and UDP frames to `udp_only.pcap` in one pass.

## Source (`examples/09_offline_split_transport.cpp`)

```cpp
#include <iostream>
#include <cstdint>
#include <zpcap.h>

#define ETHERTYPE_IPV4 0x0800

struct split_context_t {
    zpcap_dumper_t *tcp_dumper;
    zpcap_dumper_t *udp_dumper;
    uint32_t total;
    uint32_t tcp_only;
    uint32_t udp_only;
};

static bool is_ipv4(const uint8_t *packet, uint32_t caplen) {
    if (caplen < 14) return false;
    return (uint16_t(packet[12]) << 8 | packet[13]) == ETHERTYPE_IPV4;
}

static uint8_t ipv4_protocol(const uint8_t *packet, uint32_t caplen) {
    if (caplen < 34) return 0;
    uint8_t ihl = (packet[14] & 0x0f) * 4;
    if (ihl < 20 || (caplen < (uint32_t)(14 + ihl))) return 0;
    return packet[14 + 9];
}

static void packet_handler(uint8_t *user, const zpcap_pkthdr *hdr, const uint8_t *packet) {
    split_context_t *ctx = reinterpret_cast<split_context_t *>(user);
    if (!ctx || !hdr || !packet) return;

    ctx->total++;
    if (!is_ipv4(packet, hdr->caplen)) return;

    uint8_t proto = ipv4_protocol(packet, hdr->caplen);
    if (proto == 6 && ctx->tcp_dumper) {
        ctx->tcp_only++;
        zpcap_dump((uint8_t *)ctx->tcp_dumper, hdr, packet);
    } else if (proto == 17 && ctx->udp_dumper) {
        ctx->udp_only++;
        zpcap_dump((uint8_t *)ctx->udp_dumper, hdr, packet);
    }
}

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *input = (argc > 1) ? argv[1] : "output_c_test.pcap";

    zpcap_t *handle = zpcap_open_offline(input, errbuf);
    if (handle == NULL) {
        std::cerr << "failed to open offline input: " << errbuf << "\n";
        return 1;
    }

    zpcap_dumper_t *tcp_dumper = zpcap_dump_open(handle, "tcp_only.pcap");
    if (tcp_dumper == NULL) {
        std::cerr << "failed to open tcp_only.pcap\n";
        zpcap_close(handle);
        return 1;
    }

    zpcap_dumper_t *udp_dumper = zpcap_dump_open(handle, "udp_only.pcap");
    if (udp_dumper == NULL) {
        std::cerr << "failed to open udp_only.pcap\n";
        zpcap_dump_close(tcp_dumper);
        zpcap_close(handle);
        return 1;
    }

    split_context_t ctx{tcp_dumper, udp_dumper, 0, 0, 0};
    zpcap_loop(handle, -1, packet_handler, reinterpret_cast<uint8_t *>(&ctx));

    zpcap_dump_close(tcp_dumper);
    zpcap_dump_close(udp_dumper);
    zpcap_close(handle);

    std::cout << "input packets: " << ctx.total << "\n";
    std::cout << "tcp packets:   " << ctx.tcp_only << "\n";
    std::cout << "udp packets:   " << ctx.udp_only << "\n";
    std::cout << "written:      tcp_only.pcap and udp_only.pcap\n";
    return 0;
}
```

## Build and run

```bash
zig build
g++ -std=c++11 -o docs/examples/cpp11-offline-transport-split examples/09_offline_split_transport.cpp -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/cpp11-offline-transport-split
```

## What this shows

- One offline pass, two output streams.
- Protocol-aware branching in callback context.
- Reusing metadata and zero-copy packet memory in C++.
