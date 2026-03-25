#include <stdio.h>
#include <stdint.h>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *pkthdr, const uint8_t *packet) {
    (void)user; // Unused
    printf("Captured packet! Length: %d bytes | Timestamp: %d.%06d\n", 
           pkthdr->len, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
}

int main() {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    
    printf("Opening live capture on loopback ('lo')...\n");
    zpcap_t *handle = zpcap_open_live("lo", 65535, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Failed to open interface: %s\n", errbuf);
        return 1;
    }
    
    printf("Capturing exactly 5 packets. Try running 'ping 127.0.0.1'...\n");
    zpcap_loop(handle, 5, packet_handler, NULL);
    
    printf("Capture complete!\n");
    zpcap_close(handle);
    
    return 0;
}
