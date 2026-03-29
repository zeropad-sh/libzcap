#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <zpcap.h>

static void fill_sample_packet(uint8_t *packet, size_t *len) {
    static const uint8_t payload[14] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: ff:ff:ff:ff:ff:ff
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src: fake local mac
        0x08, 0x00,                         // ethertype IPv4
    };

    memset(packet, 0, 60);
    memcpy(packet, payload, sizeof(payload));
    *len = 60;
}

int main(int argc, char **argv) {
    const char *device = (argc > 1) ? argv[1] : "lo";
    char errbuf[ZPCAP_ERRBUF_SIZE];

    zpcap_t *handle = zpcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "open_live failed: %s\n", errbuf);
        return 1;
    }

    uint8_t packet[60];
    size_t packet_len = 0;
    fill_sample_packet(packet, &packet_len);

    if (zpcap_sendpacket(handle, packet, (int)packet_len) != 0) {
        fprintf(stderr, "sendpacket failed: %s\n", errbuf);
        fprintf(stderr, "Try running as root/admin and allow write on interface.\n");
        zpcap_close(handle);
        return 1;
    }

    if (zpcap_send(handle, packet, (int)packet_len) != 0) {
        fprintf(stderr, "send failed: %s\n", errbuf);
        fprintf(stderr, "Try running as root/admin and allow write on interface.\n");
        zpcap_close(handle);
        return 1;
    }

    printf("send and sendpacket completed on %s\n", device);
    zpcap_close(handle);
    return 0;
}
