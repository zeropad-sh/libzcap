# C++11 Example: Event-Loop Capture

This example shows a non-blocking, async-style loop that uses
`zpcap_get_selectable_fd` when available and falls back to polling when the
handle cannot be integrated into `select()`.

## Source (`examples/18_async_select.cpp`)

```cpp
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <chrono>
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
    const int max_packets = (argc > 2) ? std::atoi(argv[2]) : 20;

    zpcap_t *handle = zpcap_open_live(device, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "open_live failed: " << errbuf << "\n";
        return 1;
    }

    int fd = zpcap_get_selectable_fd(handle);
    if (fd < 0) {
        std::cout << "get_selectable_fd unsupported, using non-blocking polling fallback.\n";
        if (zpcap_setnonblock(handle, 1, errbuf) != 0) {
            std::cerr << "setnonblock failed: " << errbuf << "\n";
            zpcap_close(handle);
            return 1;
        }
    } else {
        if (zpcap_setnonblock(handle, 1, errbuf) != 0) {
            std::cerr << "setnonblock failed: " << errbuf << "\n";
            zpcap_close(handle);
            return 1;
        }
    }

    zpcap_pkthdr *hdr = nullptr;
    const uint8_t *pkt = nullptr;
    int handled = 0;
#ifdef _WIN32
    if (fd >= 0) {
        std::cout << "Windows select backend is unavailable; using non-blocking polling fallback.\n";
        fd = -1;
    }
#endif

    while (handled < max_packets) {
#ifndef _WIN32
        if (fd >= 0) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);

            timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int ready = select(fd + 1, &fds, nullptr, nullptr, &timeout);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "select failed: " << errno << "\n";
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
            std::cout << "packet=" << handled
                      << " caplen=" << hdr->caplen
                      << " len=" << hdr->len
                      << " ts=" << hdr->ts.tv_sec << "." << hdr->ts.tv_usec << "\n";
            continue;
        }

        if (rc == -2) {
            break;
        }

        if (rc == 0) {
            if (fd < 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            continue;
        }

        std::cerr << "next_ex returned error code: " << rc << "\n";
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
./examples/build/18_async_select_cpp
```

## What this shows

- event-driven readiness with `zpcap_get_selectable_fd` where supported
- non-blocking capture semantics via `zpcap_setnonblock`
- graceful fallback when file descriptor path is unavailable
