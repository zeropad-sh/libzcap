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
