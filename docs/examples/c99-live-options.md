# C99 Example: Live Capture With Runtime Options

This example shows a practical production pattern:

- choose device, filter expression, packet count, and output file from arguments,
- apply BPF once at startup,
- write packets to a dump file from the callback context.

## Source (`examples/10_live_capture_options.c`)

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <zpcap.h>

typedef struct {
    zpcap_dumper_t *dumper;
    uint32_t processed;
    uint32_t dumped;
    const char *filter;
} capture_context_t;

static void packet_handler(uint8_t *user, const zpcap_pkthdr *hdr, const uint8_t *packet) {
    (void)packet;
    capture_context_t *ctx = (capture_context_t *)user;
    if (!ctx || !hdr) return;

    ctx->processed++;
    if (ctx->dumper) {
        zpcap_dump((uint8_t *)ctx->dumper, hdr, packet);
        ctx->dumped++;
    }

    printf("%u bytes @ %u.%06u", hdr->len, hdr->ts.tv_sec, hdr->ts.tv_usec);
    if (ctx->filter) {
        printf(" [filter=%s]", ctx->filter);
    }
    printf("\n");
}

static int parse_int_arg(const char *value, int fallback) {
    if (value == NULL || value[0] == '\0') return fallback;
    return atoi(value);
}

int main(int argc, char **argv) {
    const char *device = (argc > 1) ? argv[1] : "lo";
    const char *filter = (argc > 2) ? argv[2] : NULL;
    const int limit = parse_int_arg((argc > 3) ? argv[3] : NULL, 25);
    const char *out = (argc > 4) ? argv[4] : NULL;

    if (limit <= 0) {
        fprintf(stderr, "packet limit must be > 0\\n");
        return 1;
    }

    char errbuf[ZPCAP_ERRBUF_SIZE];
    zpcap_t *handle = zpcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "failed to open live capture on %s: %s\\n", device, errbuf);
        return 1;
    }

    zpcap_dumper_t *dumper = NULL;
    if (out != NULL && out[0] != '\\0') {
        dumper = zpcap_dump_open(handle, out);
        if (dumper == NULL) {
            fprintf(stderr, "failed to open dump file %s\\n", out);
            zpcap_close(handle);
            return 1;
        }
    }

    struct zpcap_bpf_program program;
    if (filter && filter[0] != '\\0') {
        if (zpcap_compile(handle, &program, filter, 1, ZPCAP_NETMASK_UNKNOWN) != 0) {
            fprintf(stderr, "invalid filter expression: %s\\n", filter);
            if (dumper) zpcap_dump_close(dumper);
            zpcap_close(handle);
            return 1;
        }

        if (zpcap_setfilter(handle, &program) != 0) {
            fprintf(stderr, "failed to apply filter: %s\\n", filter);
            zpcap_freecode(&program);
            if (dumper) zpcap_dump_close(dumper);
            zpcap_close(handle);
            return 1;
        }
        zpcap_freecode(&program);
    }

    capture_context_t ctx = {dumper, 0, 0, filter};
    printf("capturing up to %d packets on %s", limit, device);
    if (filter && filter[0] != '\\0') {
        printf(" with filter '%s'", filter);
    }
    if (out && out[0] != '\\0') {
        printf(" -> %s", out);
    }
    printf("\\n");

    zpcap_loop(handle, limit, packet_handler, (uint8_t *)&ctx);

    if (dumper) zpcap_dump_close(dumper);
    zpcap_close(handle);

    printf("capture complete: packets=%u written=%u\\n", ctx.processed, ctx.dumped);
    return 0;
}
```

## Build and run

```bash
zig build
gcc -std=c99 -o docs/examples/c99-live-options examples/10_live_capture_options.c -Iinclude -Lzig-out/lib -lzcap
LD_LIBRARY_PATH=zig-out/lib ./docs/examples/c99-live-options lo "tcp port 80" 25 filtered.pcap
```

## What this shows

- Runtime options keep one binary useful in production.
- Compile/apply a BPF filter only once at startup.
- Reuse callback context to keep counters and dump handles.
