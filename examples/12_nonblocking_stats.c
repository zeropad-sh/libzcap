#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <zpcap.h>

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *path = (argc > 1) ? argv[1] : "tests/sample.pcap";
    zpcap_stat_t stats = {0};
    uint64_t handled = 0;

    zpcap_t *handle = zpcap_open_offline(path, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed opening offline capture: %s\n", errbuf);
        return 1;
    }

    if (zpcap_setnonblock(handle, 1, errbuf) != 0) {
        fprintf(stderr, "Failed to switch non-block mode: %s\n", errbuf);
        zpcap_close(handle);
        return 1;
    }

    printf("zpcap_getnonblock => %d\n", zpcap_getnonblock(handle, errbuf));

    zpcap_pkthdr *hdr = NULL;
    const uint8_t *pkt = NULL;
    while (1) {
        const zpcap_pkthdr *out_hdr = NULL;
        int rc = zpcap_next_ex(handle, (zpcap_pkthdr **)&out_hdr, (const uint8_t **)&pkt);
        if (rc == 1) {
            hdr = (zpcap_pkthdr *)out_hdr;
            handled++;
            printf("packet=%" PRIu64 " len=%u ts=%d.%06d\n", handled, hdr->len, hdr->ts.tv_sec, hdr->ts.tv_usec);
            continue;
        }

        if (rc == -2) {
            break; // EOF for offline captures
        }

        if (rc == 0) {
            continue;
        }

        fprintf(stderr, "next_ex returned error code: %d\n", rc);
        break;
    }

    if (zpcap_stats(handle, &stats) != 0) {
        fprintf(stderr, "stats failed: %s\n", errbuf);
        zpcap_close(handle);
        return 1;
    }

    printf("zpcap_stats: ps_recv=%" PRIu32 " ps_drop=%" PRIu32 " ps_ifdrop=%" PRIu32 "\n",
           stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
    zpcap_close(handle);
    return 0;
}
