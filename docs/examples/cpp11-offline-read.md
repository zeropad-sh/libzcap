# C++11 Example: Offline Read

This is a C++11 example that reads packets from a local `.pcap` file.

## Source (`examples/03_offline_read.cpp`)

```cpp
#include <iostream>
#include <cstdint>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *h, const uint8_t *) {
    (void)user;
    std::cout << "Packet len=" << h->len
              << " ts=" << h->ts.tv_sec << "." << h->ts.tv_usec << "\n";
}

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *path = (argc > 1) ? argv[1] : "tests/sample.pcap";

    zpcap_t *handle = zpcap_open_offline(path, errbuf);
    if (handle == nullptr) {
        std::cerr << "Failed to open offline file: " << errbuf << "\n";
        return 1;
    }

    zpcap_loop(handle, -1, packet_handler, nullptr);
    zpcap_close(handle);
    return 0;
}
```

## Build and run

```bash
zig build
g++ -std=c++11 -o docs/examples/cpp11-offline-read examples/03_offline_read.cpp -Iinclude -Lzig-out/lib -lzcap
./docs/examples/cpp11-offline-read tests/sample.pcap
```

On Linux/macOS:

```bash
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/cpp11-offline-read tests/sample.pcap
```
