#include <stdio.h>
#include <stdint.h>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *pkthdr, const uint8_t *packet) {
    (void)user; (void)packet;
    printf("[Verified] Caught packet matching BPF filter! Length: %d\n", pkthdr->len);
}

int main() {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    zpcap_t *handle = zpcap_open_live("lo", 65535, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Failed to open networking socket: %s\n", errbuf);
        return 1;
    }

    struct zpcap_bpf_program fp;
    
    // Compile a robust string expression mapping structurally back down to standard BPF arrays
    if (zpcap_compile(handle, &fp, "tcp port 80", 1, ZPCAP_NETMASK_UNKNOWN) == -1) {
        printf("Failed to cleanly compile packet filter.\n");
        return 1;
    }
    
    // Dynamically drop the raw compiled Instructions deep into the Linux Kernel hook
    if (zpcap_setfilter(handle, &fp) == -1) {
        printf("Failed to securely attach the BPF bytecode to kernel module.\n");
        return 1;
    }

    printf("Socket filtered recursively via raw BPF instructions. Awaiting exclusively TCP Port 80...\n");
    zpcap_loop(handle, 5, packet_handler, NULL);
    
    zpcap_freecode(&fp);
    zpcap_close(handle);
    return 0;
}
