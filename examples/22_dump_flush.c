#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <zpcap.h>

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "tests/sample.pcap";
    const char *out = (argc > 2) ? argv[2] : "flush_output.pcap";
    char errbuf[ZPCAP_ERRBUF_SIZE];

    zpcap_t *handle = zpcap_open_offline(path, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "zpcap_open_offline failed: %s\n", errbuf);
        return 1;
    }

    zpcap_dumper_t *dumper = zpcap_dump_open(handle, out);
    if (dumper == NULL) {
        fprintf(stderr, "zpcap_dump_open failed for %s\n", out);
        zpcap_close(handle);
        return 1;
    }

    zpcap_pkthdr *hdr = NULL;
    const uint8_t *packet = NULL;
    uint32_t written = 0;
    int rc = 0;

    while ((rc = zpcap_next_ex(handle, &hdr, &packet)) == 1) {
        ++written;
        zpcap_dump((uint8_t *)dumper, hdr, packet);

        if (written <= 2) {
            printf(
                "captured packet=%" PRIu32 " caplen=%" PRIu32 " len=%" PRIu32 "\n",
                written,
                hdr->caplen,
                hdr->len
            );
        }

        if (written % 2 == 0) {
            const int flush_rc = zpcap_dump_flush(dumper);
            printf("flush checkpoint at packet=%" PRIu32 ": rc=%d\n", written, flush_rc);
            if (flush_rc != 0) {
                fprintf(stderr, "zpcap_dump_flush failed at packet=%" PRIu32 "\n", written);
                break;
            }
        }
    }

    const int final_flush = zpcap_dump_flush(dumper);
    printf("final zpcap_dump_flush rc=%d\n", final_flush);
    printf("written packets=%" PRIu32 "\n", written);

    if (rc < 0 && rc != -2) {
        fprintf(stderr, "zpcap_next_ex failed: %d\n", rc);
        zpcap_dump_close(dumper);
        zpcap_close(handle);
        return 1;
    }

    zpcap_dump_close(dumper);
    zpcap_close(handle);
    return 0;
}
