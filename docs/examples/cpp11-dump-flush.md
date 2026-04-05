# C++11 Example: Offline Dump Flush

This example demonstrates the same dump durability flow as the C sample using
`zpcap_dump_flush` in C++11.

## Source (`examples/22_dump_flush.cpp`)

```cpp
#include <cstdint>
#include <cinttypes>
#include <iostream>
#include <zpcap.h>

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "tests/sample.pcap";
    const char *out = (argc > 2) ? argv[2] : "flush_output.pcap";
    char errbuf[ZPCAP_ERRBUF_SIZE];

    auto *handle = zpcap_open_offline(path, errbuf);
    if (handle == nullptr) {
        std::cerr << "zpcap_open_offline failed: " << errbuf << '\n';
        return 1;
    }

    auto *dumper = zpcap_dump_open(handle, out);
    if (dumper == nullptr) {
        std::cerr << "zpcap_dump_open failed for " << out << '\n';
        zpcap_close(handle);
        return 1;
    }

    zpcap_pkthdr *hdr = nullptr;
    const uint8_t *packet = nullptr;
    uint32_t written = 0;
    int rc = 0;

    while ((rc = zpcap_next_ex(handle, &hdr, &packet)) == 1) {
        ++written;
        zpcap_dump(reinterpret_cast<uint8_t *>(dumper), hdr, packet);

        if (written <= 2) {
            std::cout << "captured packet=" << written
                      << " caplen=" << hdr->caplen
                      << " len=" << hdr->len << '\n';
        }

        if (written % 2 == 0) {
            const int flush_rc = zpcap_dump_flush(dumper);
            std::cout << "flush checkpoint at packet=" << written << " rc=" << flush_rc << '\n';
            if (flush_rc != 0) {
                std::cerr << "zpcap_dump_flush failed at packet=" << written << '\n';
                break;
            }
        }
    }

    const int final_flush = zpcap_dump_flush(dumper);
    std::cout << "final zpcap_dump_flush rc=" << final_flush << '\n';
    std::cout << "written packets=" << written << '\n';

    zpcap_dump_close(dumper);
    zpcap_close(handle);
    return rc < 0 ? 1 : 0;
}
```

## Build and run

```bash
cmake -S examples -B examples/build -DLIBZCAP_ROOT="$(pwd)" -DLIBZCAP_BUILD_DIR="$(pwd)/zig-out"
cmake --build examples/build --target 22_dump_flush_cpp
./examples/build/22_dump_flush_cpp
```

## What this shows

- The modern API surface is identical across C99 and C++11 usage.
- Frequent calls to `zpcap_dump_flush()` can be used to bound data loss windows.
