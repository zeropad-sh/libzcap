#include <iostream>
#include <stdint.h>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *pkthdr, const uint8_t *packet) {
    (void)user; (void)packet; // Unused
    std::cout << "[Offline] Parsed historical trace packet: " << pkthdr->len << " bytes captured at " << pkthdr->ts.tv_sec << "s\n";
}

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    
    const char *target = (argc > 1) ? argv[1] : "output.pcap";
    
    // Natively open standard .pcap traffic traces utilizing Zig's offline Reader
    zpcap_t *handle = zpcap_open_offline(target, errbuf);
    
    if (handle == nullptr) {
        std::cerr << "Failed to open offline PCAP for trace parsing: " << errbuf << "\n";
        return 1;
    }
    
    std::cout << "Successfully loaded .pcap trace. Unrolling internal stream...\n";
    // Passing -1 evaluates indefinitely evaluating precisely up to the internal EOF threshold dynamically
    zpcap_loop(handle, -1, packet_handler, nullptr);
    
    zpcap_close(handle);
    std::cout << "Done reading buffer trace.\n";
    return 0;
}
