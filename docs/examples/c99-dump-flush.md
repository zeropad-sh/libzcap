# C99 Example: Offline Dump Flush

This example shows the file-write durability API introduced for long-running dump
workloads: `zpcap_dump_flush`.

It reads packets from an offline trace, writes them via `zpcap_dump`, and calls
`zpcap_dump_flush` periodically and once more before exit.

## Source (`examples/22_dump_flush.c`)

```c
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
    int rc;

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

    zpcap_dump_close(dumper);
    zpcap_close(handle);
    return rc < 0 ? 1 : 0;
}
```

## Build and run

```bash
cmake -S examples -B examples/build -DLIBZCAP_ROOT="$(pwd)" -DLIBZCAP_BUILD_DIR="$(pwd)/zig-out"
cmake --build examples/build --target 22_dump_flush_c
./examples/build/22_dump_flush_c
```

## What this shows

- `zpcap_dump_flush()` keeps offline file durability deterministic.
- Periodic checkpoints are visible by packet count.
- Works with pre-captured offline traces and is safe to use in CI smoke checks.
