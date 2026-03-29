# C++11 Example: Find Devices and Default Device

This example shows `zpcap_findalldevs` and `zpcap_lookupdev`.

## Source (`examples/15_findalldevs_lookupdev.cpp`)

```cpp
#include <iostream>
#include <zpcap.h>

int main() {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    zpcap_if_t *devices = nullptr;

    if (zpcap_findalldevs(&devices, errbuf) != 0) {
        std::cerr << "findalldevs failed: " << errbuf << "\n";
        return 1;
    }

    std::cout << "Devices returned by zpcap_findalldevs:\n";
    for (zpcap_if_t *dev = devices; dev != nullptr; dev = dev->next) {
        if (dev->name != nullptr) {
            std::cout << "  - " << dev->name;
            if (dev->description != nullptr) {
                std::cout << " (" << dev->description << ")";
            }
            std::cout << "\n";
        }
    }

    const char *default_dev = zpcap_lookupdev(errbuf);
    if (default_dev == nullptr) {
        std::cerr << "lookupdev failed: " << errbuf << "\n";
        zpcap_freealldevs(devices);
        return 1;
    }

    std::cout << "Default device from zpcap_lookupdev: " << default_dev << "\n";
    zpcap_freealldevs(devices);
    return 0;
}
```

## Build and run

```bash
zig build
g++ -std=c++11 -o docs/examples/cpp11-find-devices examples/15_findalldevs_lookupdev.cpp -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/cpp11-find-devices
```

## What this shows

- how to list all capture interfaces
- how to resolve a default interface
- how to clean up with `zpcap_freealldevs`
