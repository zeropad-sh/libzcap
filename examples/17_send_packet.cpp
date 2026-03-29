#include <cstring>
#include <cstdint>
#include <iostream>
#include <zpcap.h>

static void fill_sample_packet(uint8_t *packet, size_t *len) {
    static const uint8_t prefix[14] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // source
        0x08, 0x00,                         // Ethernet type IPv4
    };

    std::memset(packet, 0, 60);
    std::memcpy(packet, prefix, sizeof(prefix));
    *len = 60;
}

int main(int argc, char **argv) {
    const char *device = (argc > 1) ? argv[1] : "lo";
    char errbuf[ZPCAP_ERRBUF_SIZE];

    zpcap_t *handle = zpcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "open_live failed: " << errbuf << "\n";
        return 1;
    }

    uint8_t packet[60];
    size_t packet_len = 0;
    fill_sample_packet(packet, &packet_len);

    if (zpcap_sendpacket(handle, packet, static_cast<int>(packet_len)) != 0) {
        std::cerr << "sendpacket failed: " << errbuf << "\n";
        std::cerr << "Run with admin/root and allow interface write permissions.\n";
        zpcap_close(handle);
        return 1;
    }

    if (zpcap_send(handle, packet, static_cast<int>(packet_len)) != 0) {
        std::cerr << "send failed: " << errbuf << "\n";
        std::cerr << "Run with admin/root and allow interface write permissions.\n";
        zpcap_close(handle);
        return 1;
    }

    std::cout << "send and sendpacket completed on " << device << "\n";
    zpcap_close(handle);
    return 0;
}
