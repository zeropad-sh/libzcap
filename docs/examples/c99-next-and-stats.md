# C99 Example: Pull API + Packet Statistics

This example uses `zpcap_next` to pull packets in a tight loop and keep simple counters.

## Source (`examples/05_next_and_stats.c`)

```c
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <zpcap.h>

int main(void) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    zpcap_t *handle = zpcap_open_live("lo", 65535, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Failed to open interface: %s\n", errbuf);
        return 1;
    }

    zpcap_pkthdr hdr;
    uint64_t total_pkts = 0;
    uint64_t total_bytes = 0;
    uint64_t ipv4_pkts = 0;

    printf("Using zpcap_next for direct pull-based capture.\n");
    printf("Collecting first 20 packets...\n");

    while (total_pkts < 20) {
        const uint8_t *packet = zpcap_next(handle, &hdr);
        if (packet == NULL) {
            /* no packet available yet, keep polling */
            continue;
        }

        total_pkts++;
        total_bytes += hdr.len;

        if (hdr.caplen >= 14) {
            const uint16_t ether_type = ((uint16_t)packet[12] << 8) | (uint16_t)packet[13];
            if (ether_type == 0x0800) {
                ipv4_pkts++;
            }
        }

        printf("packet=%" PRIu64 " len=%" PRIu32 " ts=%" PRIu32 ".%" PRIu32 "\n",
               total_pkts, hdr.len, hdr.ts.tv_sec, hdr.ts.tv_usec);
    }

    printf("\nDone. packets=%" PRIu64 ", ipv4=%" PRIu64 ", bytes=%" PRIu64 "\n",
           total_pkts, ipv4_pkts, total_bytes);
    zpcap_close(handle);
    return 0;
}
```

## Build and run

```bash
zig build
gcc -std=c99 -o docs/examples/c99-next-and-stats examples/05_next_and_stats.c -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/c99-next-and-stats
```

## What this shows

- You control packet reads yourself (pull model), instead of using callback loop.
- You can compute counters in your app while capturing.
- You can add cheap protocol checks in the callback-free path.
