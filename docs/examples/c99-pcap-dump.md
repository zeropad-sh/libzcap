# C99 Example: Save Live Traffic to PCAP

This example opens a live interface, applies a callback, and writes packets into `output.pcap`.

## Source (`examples/02_pcap_dump.c`)

```c
#include <stdio.h>
#include <stdint.h>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *h, const uint8_t *packet) {
    if (user != NULL) {
        zpcap_dump(user, h, packet);
    }
}

int main(void) {
    char errbuf[ZPCAP_ERRBUF_SIZE];

    zpcap_t *handle = zpcap_open_live("lo", 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Failed to open interface: %s\n", errbuf);
        return 1;
    }

    zpcap_dumper_t *dumper = zpcap_dump_open(handle, "output_c_test.pcap");
    if (dumper == NULL) {
        printf("Failed to open dumper.\n");
        zpcap_close(handle);
        return 1;
    }

    zpcap_loop(handle, 10, packet_handler, (uint8_t *)dumper);

    zpcap_dump_close(dumper);
    zpcap_close(handle);
    return 0;
}
```

## Build and run

```bash
zig build
gcc -std=c99 -o docs/examples/c99-pcap-dump examples/02_pcap_dump.c -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/c99-pcap-dump
```

## Output

- Produces `output_c_test.pcap` in the current directory.
- Use any Wireshark/tcpdump-compatible reader to inspect the capture.
