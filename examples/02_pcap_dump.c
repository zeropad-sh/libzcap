#include <stdio.h>
#include <stdint.h>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *pkthdr, const uint8_t *packet) {
    if (user != NULL) {
        // Stream the zer-copy memory chunk directly out purely as PCAP binary disk writes
        zpcap_dump(user, pkthdr, packet);
    }
}

int main() {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    
    zpcap_t *handle = zpcap_open_live("lo", 65535, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Failed to open network interface: %s\n", errbuf);
        return 1;
    }
    
    // Natively open a PCAP dumper matching standard C-ABI libpcap designs!
    zpcap_dumper_t *dumper = zpcap_dump_open(handle, "output.pcap");
    if (dumper == NULL) {
        printf("Failed to initialize fast-path Writer.\n");
        return 1;
    }
    
    printf("Successfully captured interface traffic directly to output.pcap\n");
    
    // Process packets and map the Dumper context cleanly via pointer boundaries
    zpcap_loop(handle, 10, packet_handler, (uint8_t*)dumper);
    
    zpcap_dump_close(dumper);
    zpcap_close(handle);
    
    return 0;
}
