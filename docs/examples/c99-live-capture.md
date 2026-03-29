# C99 Example: Live Capture

This example opens an interface and captures the first 5 packets with a simple callback.

## Source (`examples/01_basic_capture.c`)

```c
#include <stdio.h>
#include <stdint.h>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *h, const uint8_t *packet) {
    (void)user;
    (void)packet;
    printf("Packet len=%u ts=%d.%06d\n", h->len, h->ts.tv_sec, h->ts.tv_usec);
}

int main(void) {
    char errbuf[ZPCAP_ERRBUF_SIZE];

    zpcap_t *handle = zpcap_open_live("lo", 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Failed to open interface: %s\n", errbuf);
        return 1;
    }

    printf("Capturing 5 packets. Run ping on a second terminal to generate traffic.\n");
    zpcap_loop(handle, 5, packet_handler, NULL);

    zpcap_close(handle);
    return 0;
}
```

## Build and run

```bash
zig build
gcc -std=c99 -o docs/examples/c99-live-capture examples/01_basic_capture.c -Iinclude -Lzig-out/lib -lzcap
./docs/examples/c99-live-capture
```

On Linux/macOS:

```bash
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/c99-live-capture
```

## What to expect

- Callback receives raw packet references as non-owning memory views.
- `zpcap_loop` blocks until the requested packet count is reached or an unrecoverable error occurs.
