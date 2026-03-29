# C++11 Example: Non-Blocking API and Stats

This example demonstrates `zpcap_setnonblock`, `zpcap_getnonblock`, `zpcap_next_ex`, and `zpcap_stats`.

## Source (`examples/16_nonblocking_stats.cpp`)

```cpp
#include <cstdint>
#include <iostream>
#include <inttypes.h>
#include <zpcap.h>

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *path = (argc > 1) ? argv[1] : "tests/sample.pcap";

    zpcap_t *handle = zpcap_open_offline(path, errbuf);
    if (handle == nullptr) {
        std::cerr << "failed to open offline input: " << errbuf << "\n";
        return 1;
    }

    if (zpcap_setnonblock(handle, 1, errbuf) != 0) {
        std::cerr << "setnonblock failed: " << errbuf << "\n";
        zpcap_close(handle);
        return 1;
    }

    std::cout << "zpcap_getnonblock => " << zpcap_getnonblock(handle, errbuf) << "\n";

    zpcap_pkthdr *hdr = nullptr;
    const uint8_t *pkt = nullptr;
    uint64_t handled = 0;

    while (true) {
        int rc = zpcap_next_ex(handle, &hdr, &pkt);
        if (rc == 1) {
            ++handled;
            std::cout << "packet=" << handled << " len=" << hdr->len
                      << " ts=" << hdr->ts.tv_sec << "." << hdr->ts.tv_usec << "\n";
            continue;
        }
        if (rc == -2) {
            break; // EOF for offline captures
        }
        if (rc == 0) {
            continue;
        }

        std::cerr << "next_ex failed: " << rc << "\n";
        zpcap_close(handle);
        return 1;
    }

    zpcap_stat_t stats = {};
    if (zpcap_stats(handle, &stats) != 0) {
        std::cerr << "stats failed: " << errbuf << "\n";
        zpcap_close(handle);
        return 1;
    }

    std::cout << "zpcap_stats: ps_recv=" << stats.ps_recv
              << " ps_drop=" << stats.ps_drop
              << " ps_ifdrop=" << stats.ps_ifdrop << "\n";

    zpcap_close(handle);
    return 0;
}
```

## Build and run

```bash
zig build
g++ -std=c++11 -o docs/examples/cpp11-nonblocking-stats examples/16_nonblocking_stats.cpp -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/cpp11-nonblocking-stats tests/sample.pcap
```
