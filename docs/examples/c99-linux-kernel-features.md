# C99 Example: Linux Kernel Feature-Aware Capture

This example shows how to use `zpcap_detect_features`, `zpcap_kernel_version`, and
`zpcap_open_live_ex` to request modern Linux capture features and still run on
older kernels by design.

## Source (`examples/20_linux_kernel_features.c`)

```c
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zpcap.h>

static void print_features(void) {
    int major = 0;
    int minor = 0;
    int patch = 0;
    const uint32_t features = zpcap_detect_features();
    zpcap_kernel_version(&major, &minor, &patch);

    printf("Kernel: %d.%d.%d\n", major, minor, patch);
    printf("Feature mask: 0x%08" PRIx32 "\n", features);
    printf("  ring_mmap=%s\n", (features & ZPCAP_FEATURE_RING_V3) ? "yes" : "no");
    printf("  fanout=%s\n", (features & ZPCAP_FEATURE_FANOUT) ? "yes" : "no");
    printf("  busy_poll=%s\n", (features & ZPCAP_FEATURE_BUSY_POLL) ? "yes" : "no");
}

static int is_root_capture_error(const char *err) {
    return err != NULL && (strstr(err, "Permission") != NULL || strstr(err, "DENIED") != NULL);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    print_features();

    char errbuf[ZPCAP_ERRBUF_SIZE];
    const int use_ring = 1;
    zpcap_open_options opts = {
        .version = 1,
        .buffer_mode = use_ring ? ZPCAP_BUFFER_MODE_RING_MMAP : ZPCAP_BUFFER_MODE_COPY,
        .ring_block_size = 0,
        .ring_block_count = 0,
        .ring_frame_size = 0,
        .ring_frame_count = 0,
        .fanout_mode = ZPCAP_FANOUT_NONE,
        .fanout_group = 1,
        .busy_poll_usec = 0,
        .fallback_to_copy = 1,
    };

    const uint32_t features = zpcap_detect_features();
    if (features & ZPCAP_FEATURE_BUSY_POLL) {
        opts.busy_poll_usec = 2000;
        printf("Configured busy polling: 2000usec\n");
    } else {
        printf("Busy polling unavailable, skip setting.\n");
    }

    if (features & ZPCAP_FEATURE_FANOUT) {
        opts.fanout_mode = ZPCAP_FANOUT_HASH;
        opts.fanout_group = 1;
        printf("Configured fanout: hash group=1\n");
    } else {
        printf("Fanout unavailable, skip setting.\n");
    }

    const char *device = zpcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "zpcap_lookupdev failed: %s\n", errbuf);
        return 1;
    }

    zpcap_t *handle = zpcap_open_live_ex(
        device,
        65535,
        1,
        1000,
        &opts,
        errbuf
    );
    if (handle == NULL) {
        if (is_root_capture_error(errbuf)) {
            printf("Open live capture failed (expected without privileges): %s\n", errbuf);
            return 0;
        }
        fprintf(stderr, "zpcap_open_live_ex failed: %s\n", errbuf);
        return 1;
    }

    printf("Opened live handle on device: %s\n", device);
    printf("Requested mode: %s\n", use_ring ? "ring_mmap" : "copy");
    printf("Runtime mode: %s\n", (features & ZPCAP_FEATURE_RING_V3) ? "ring_mmap" : "copy");

    if (zpcap_setnonblock(handle, 1, errbuf) != 0) {
        fprintf(stderr, "setnonblock failed: %s\n", errbuf);
        zpcap_close(handle);
        return 1;
    }

    zpcap_pkthdr *hdr = NULL;
    const uint8_t *pkt = NULL;
    int handled = 0;
    for (int i = 0; i < 4; ++i) {
        const int rc = zpcap_next_ex(handle, &hdr, &pkt);
        if (rc == 1) {
            printf("captured packet %d: caplen=%u len=%u ts=%" PRIi32 ".%06" PRIu32 "\n",
                   handled + 1, hdr->caplen, hdr->len, hdr->ts.tv_sec, hdr->ts.tv_usec);
            ++handled;
        } else if (rc == 0) {
            printf("no packet available in poll cycle %d\n", i + 1);
        } else if (rc == -2) {
            printf("offline-like end-of-stream marker (should not happen in live mode)\n");
            break;
        } else {
            printf("next_ex error code: %d\n", rc);
            break;
        }
    }

    zpcap_stat_t stats;
    if (zpcap_stats(handle, &stats) == 0) {
        printf("stats: ps_recv=%" PRIu32 " ps_drop=%" PRIu32 " ps_ifdrop=%" PRIu32 "\n",
               stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
    }

    zpcap_close(handle);
    printf("Done. handled=%d\n", handled);
    return 0;
}
```

## Build and run

```bash
cmake -S examples -B examples/build -DLIBZCAP_ROOT="$(pwd)" -DLIBZCAP_BUILD_DIR="$(pwd)/zig-out"
cmake --build examples/build
./examples/build/20_linux_kernel_features_c
```

## What this shows

- Detect kernel capability bits at runtime with `zpcap_detect_features`.
- Open with `zpcap_open_live_ex` using `ring_mmap`, `fanout`, and `busy_poll` options.
- Still get deterministic behavior when permissions are missing; the example exits with code 0 and explains the reason.
- On kernels without `TPACKET_V3` or `SO_BUSY_POLL`, options are not required and behavior falls back safely.
