# C99 Example: Event-Loop Capture

This example uses `zpcap_get_selectable_fd` when available, and falls back to
non-blocking polling when no file descriptor integration exists (for example,
on Windows with some drivers).

## Source (`examples/18_async_select.c`)

```c
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <zpcap.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/select.h>
#include <unistd.h>
#endif

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *device = (argc > 1) ? argv[1] : "lo";
    const int max_packets = (argc > 2) ? atoi(argv[2]) : 20;

    zpcap_t *handle = zpcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "open_live failed: %s\n", errbuf);
        return 1;
    }

    int fd = zpcap_get_selectable_fd(handle);
    if (fd < 0) {
        fprintf(stderr, "get_selectable_fd unsupported, using non-blocking polling fallback.\n");
        if (zpcap_setnonblock(handle, 1, errbuf) != 0) {
            fprintf(stderr, "setnonblock failed: %s\n", errbuf);
            zpcap_close(handle);
            return 1;
        }
    } else {
        if (zpcap_setnonblock(handle, 1, errbuf) != 0) {
            fprintf(stderr, "setnonblock failed: %s\n", errbuf);
            zpcap_close(handle);
            return 1;
        }
    }

    zpcap_pkthdr *hdr = NULL;
    const uint8_t *pkt = NULL;
    int handled = 0;
#ifdef _WIN32
    if (fd >= 0) {
        fprintf(stderr, "Windows select backend is unavailable; using non-blocking polling fallback.\n");
        fd = -1;
    }
#endif

    while (handled < max_packets) {
#ifndef _WIN32
        if (fd >= 0) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);

            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int ready = select(fd + 1, &fds, NULL, NULL, &timeout);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                fprintf(stderr, "select failed: %d\n", errno);
                break;
            }
            if (ready == 0) {
                continue;
            }
        }
#endif

        int rc = zpcap_next_ex(handle, &hdr, &pkt);
        if (rc == 1) {
            ++handled;
            printf("packet=%d caplen=%u len=%u ts=%d.%06d\n",
                   handled, hdr->caplen, hdr->len, hdr->ts.tv_sec, hdr->ts.tv_usec);
            continue;
        }

        if (rc == -2) {
            break;
        }

        if (rc == 0) {
            if (fd < 0) {
#ifdef _WIN32
                Sleep(10);
#else
                struct timeval delay = {0, 10 * 1000};
                select(0, NULL, NULL, NULL, &delay);
#endif
                continue;
            }
            continue;
        }

        fprintf(stderr, "next_ex returned error code: %d\n", rc);
        break;
    }

    zpcap_close(handle);
    return 0;
}
```

## Build and run

```bash
cmake -S examples -B examples/build -DLIBZCAP_ROOT="$(pwd)" -DLIBZCAP_BUILD_DIR="$(pwd)/zig-out/lib"
cmake --build examples/build
./examples/build/18_async_select_c
```

## What this shows

- event-driven capture path with `zpcap_get_selectable_fd` when supported
- `zpcap_next_ex` return value handling (`1`, `0`, `-2`)
- fallback behavior when `zpcap_get_selectable_fd` is unavailable
