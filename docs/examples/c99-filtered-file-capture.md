# C99 Example: Live Filter + Dumping

This example compiles a BPF expression, applies it, and writes matching packets directly into a file.

## Source (`examples/06_filtered_capture_to_file.c`)

```c
#include <stdio.h>
#include <stdint.h>
#include <zpcap.h>

typedef struct {
    zpcap_dumper_t *dumper;
    int count;
} context_t;

static void packet_handler(uint8_t *user, const zpcap_pkthdr *hdr, const uint8_t *packet) {
    (void)packet;
    if (user == NULL || hdr == NULL) return;

    context_t *ctx = (context_t *)user;
    ctx->count++;
    printf("captured packet %d len=%u\n", ctx->count, hdr->len);

    if (ctx->dumper) {
        zpcap_dump((uint8_t *)ctx->dumper, hdr, packet);
    }
}

int main(void) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    zpcap_t *handle = zpcap_open_live("lo", 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open interface: %s\n", errbuf);
        return 1;
    }

    struct zpcap_bpf_program fp;
    if (zpcap_compile(handle, &fp, "tcp port 80", 1, ZPCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "Failed to compile filter\n");
        zpcap_close(handle);
        return 1;
    }

    if (zpcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "Failed to set filter\n");
        zpcap_freecode(&fp);
        zpcap_close(handle);
        return 1;
    }

    zpcap_dumper_t *dumper = zpcap_dump_open(handle, "filtered_tcp.pcap");
    if (dumper == NULL) {
        fprintf(stderr, "Failed to open output file for dump\n");
        zpcap_freecode(&fp);
        zpcap_close(handle);
        return 1;
    }

    context_t ctx = {
        .dumper = dumper,
        .count = 0,
    };

    zpcap_loop(handle, 20, packet_handler, (uint8_t *)&ctx);

    zpcap_dump_close(dumper);
    zpcap_freecode(&fp);
    zpcap_close(handle);
    printf("Saved %d packets into filtered_tcp.pcap\n", ctx.count);
    return 0;
}
```

## Build and run

```bash
zig build
gcc -std=c99 -o docs/examples/c99-filtered-file-capture examples/06_filtered_capture_to_file.c -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/c99-filtered-file-capture
```

## What this shows

- Compile-time filter string setup with `zpcap_compile`.
- Live filter push-down with `zpcap_setfilter`.
- Safe packet dump routing using callback user context.
