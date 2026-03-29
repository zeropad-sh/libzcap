#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <zpcap.h>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_VLAN 0x8100

typedef struct {
    uint64_t total;
    uint64_t ipv4;
    uint64_t ipv6;
    uint64_t arp;
    uint64_t vlan;
    uint64_t other;
} protocol_stats_t;

static uint16_t read_u16be(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static void packet_handler(uint8_t *user, const zpcap_pkthdr *hdr, const uint8_t *packet) {
    protocol_stats_t *stats = (protocol_stats_t *)user;
    if (!stats || !hdr || !packet) return;

    if (hdr->caplen < 14) {
        stats->other++;
        stats->total++;
        return;
    }

    uint16_t ethertype = read_u16be(packet + 12);
    if (ethertype == ETHERTYPE_VLAN) {
        if (hdr->caplen >= 18) {
            ethertype = read_u16be(packet + 16);
            stats->vlan++;
        }
    }

    stats->total++;
    if (ethertype == ETHERTYPE_IPV4) {
        stats->ipv4++;
    } else if (ethertype == ETHERTYPE_IPV6) {
        stats->ipv6++;
    } else if (ethertype == ETHERTYPE_ARP) {
        stats->arp++;
    } else {
        stats->other++;
    }
}

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *path = (argc > 1) ? argv[1] : "tests/sample.pcap";

    zpcap_t *handle = zpcap_open_offline(path, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "failed to open offline input %s: %s\n", path, errbuf);
        return 1;
    }

    protocol_stats_t stats = {0};

    printf("datalink: %d\n", zpcap_datalink(handle));
    zpcap_loop(handle, -1, packet_handler, (uint8_t *)&stats);
    zpcap_close(handle);

    printf("packets processed: %" PRIu64 "\n", stats.total);
    printf("ipv4:             %" PRIu64 "\n", stats.ipv4);
    printf("ipv6:             %" PRIu64 "\n", stats.ipv6);
    printf("arp:              %" PRIu64 "\n", stats.arp);
    printf("vlan tagged:      %" PRIu64 "\n", stats.vlan);
    printf("other:            %" PRIu64 "\n", stats.other);

    return 0;
}
