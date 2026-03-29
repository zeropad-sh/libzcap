# C99 Example: Live BPF Filter

This example compiles a BPF expression and attaches it before capture starts.

## Source (`examples/04_bpf_filter.c`)

```c
#include <stdio.h>
#include <stdint.h>
#include <zpcap.h>

void packet_handler(uint8_t *user, const zpcap_pkthdr *h, const uint8_t *packet) {
    (void)user;
    (void)packet;
    printf("Matched packet: len=%u\n", h->len);
}

int main(void) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    zpcap_t *handle = zpcap_open_live("lo", 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Failed to open interface: %s\n", errbuf);
        return 1;
    }

    struct zpcap_bpf_program fp;
    if (zpcap_compile(handle, &fp, "tcp port 80", 1, ZPCAP_NETMASK_UNKNOWN) == -1) {
        printf("Failed to compile filter.\n");
        zpcap_close(handle);
        return 1;
    }

    if (zpcap_setfilter(handle, &fp) == -1) {
        printf("Failed to apply filter.\n");
        zpcap_freecode(&fp);
        zpcap_close(handle);
        return 1;
    }

    zpcap_loop(handle, 5, packet_handler, NULL);

    zpcap_freecode(&fp);
    zpcap_close(handle);
    return 0;
}
```

## Build and run

```bash
zig build
gcc -std=c99 -o docs/examples/c99-bpf-filter examples/04_bpf_filter.c -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/c99-bpf-filter
```

## Notes

- Expression parsing here is minimal and currently aligned with the repository filter support.
- `zpcap_compile`/`zpcap_setfilter` still follows the classic `libpcap` workflow for compatibility.
