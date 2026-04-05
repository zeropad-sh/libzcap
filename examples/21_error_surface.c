#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <zpcap.h>

static void on_packet(uint8_t *user, const zpcap_pkthdr *hdr, const uint8_t *pkt) {
    (void)pkt;

    uint64_t *count = (uint64_t *)user;
    *count += 1;

    if (*count <= 2) {
        printf("dispatch packet=%" PRIu64 " caplen=%" PRIu32 " len=%" PRIu32 "\n",
               *count, hdr->caplen, hdr->len);
    }
}

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *path = (argc > 1) ? argv[1] : "tests/sample.pcap";

    printf("zpcap_lib_version: %s\n", zpcap_lib_version());
    printf("zpcap_strerror invalid arg: %s\n", zpcap_strerror(ZPCAP_ERROR_INVALID_ARGUMENT));
    printf("zpcap_strerror i/o: %s\n", zpcap_strerror(ZPCAP_ERROR_IO));

    zpcap_t *probe = zpcap_open_offline("this-file-does-not-exist.pcap", errbuf);
    if (probe != NULL) {
        zpcap_close(probe);
        fprintf(stderr, "unexpectedly opened missing file\n");
        return 1;
    }
    zpcap_perror(NULL, "missing-file open");

    zpcap_t *handle = zpcap_open_offline(path, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "zpcap_open_offline failed: %s\n", errbuf);
        return 1;
    }

    if (zpcap_setnonblock(handle, 2, errbuf) != 0) {
        printf("expected setnonblock failure: %s\n", errbuf);
        zpcap_perror(handle, "invalid nonblock");
    } else {
        printf("unexpected setnonblock return value\n");
        zpcap_close(handle);
        return 1;
    }

    uint64_t packet_count = 0;
    const int rc = zpcap_dispatch(handle, -1, on_packet, (uint8_t *)&packet_count);
    printf("zpcap_dispatch returned=%d\n", rc);
    printf("dispatch packets: %" PRIu64 "\n", packet_count);
    if (rc < 0) {
        zpcap_perror(handle, "dispatch");
        zpcap_close(handle);
        return 1;
    }

    zpcap_close(handle);
    return 0;
}
