#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <iostream>
#include <thread>
#include <zpcap.h>

#if defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
#include <windows.h>
#else
#include <sys/select.h>
#include <unistd.h>
#endif

namespace {
static void print_usage() {
    std::cerr << "Usage:\n"
              << "  19_async_native_wait --live <device> [max_packets]\n"
              << "  19_async_native_wait --offline <pcap_file> [max_packets]\n"
              << "  19_async_native_wait <pcap_file> [max_packets]\n";
}
}

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *mode = "offline";
    const char *source = "tests/sample.pcap";
    const int default_packets = 20;
    int max_packets = default_packets;
    bool use_live = false;
    int arg_index = 1;

    if (argc > 1) {
        if (std::strcmp(argv[1], "--live") == 0) {
            if (argc < 3) {
                print_usage();
                return 1;
            }
            mode = "--live";
            source = argv[2];
            arg_index = 3;
            use_live = true;
        } else if (std::strcmp(argv[1], "--offline") == 0) {
            if (argc < 3) {
                print_usage();
                return 1;
            }
            mode = "--offline";
            source = argv[2];
            arg_index = 3;
        } else {
            source = argv[1];
            arg_index = 2;
            mode = "offline";
        }
    }

    if (argc > arg_index) {
        const int requested = std::atoi(argv[arg_index]);
        if (requested > 0) {
            max_packets = requested;
        }
    }

    zpcap_t *handle = nullptr;
    if (std::strcmp(mode, "--live") == 0) {
        std::cout << "Opening live capture on " << source << '\n';
        handle = zpcap_open_live(source, 65535, 1, 1000, errbuf);
    } else {
        std::cout << "Opening offline capture from " << source << '\n';
        handle = zpcap_open_offline(source, errbuf);
    }

    if (handle == nullptr) {
        std::cerr << "open failed: " << errbuf << '\n';
        return 1;
    }

    if (zpcap_setnonblock(handle, 1, errbuf) != 0) {
        std::cerr << "setnonblock failed: " << errbuf << '\n';
        zpcap_close(handle);
        return 1;
    }

    void *event_handle = nullptr;
    int fd = -1;
    int ready_mode = 0; // 0 = sleep poll, 1 = select, 2 = wait object
    if (use_live) {
        fd = zpcap_get_selectable_fd(handle);
        event_handle = zpcap_getevent(handle);
        if (fd >= 0) {
            ready_mode = 1;
            std::cout << "Ready mode: select() fd (" << fd << ")\n";
        } else if (event_handle != nullptr) {
            ready_mode = 2;
            std::cout << "Ready mode: native event handle\n";
        } else {
            ready_mode = 0;
            std::cout << "Ready mode: timed poll fallback\n";
        }
    } else {
        ready_mode = 0;
        std::cout << "Ready mode: offline polling fallback\n";
    }

    zpcap_pkthdr *hdr = nullptr;
    const uint8_t *pkt = nullptr;
    int handled = 0;
    int iterations = 0;

    while (handled < max_packets) {
        ++iterations;
        if (use_live) {
            if (ready_mode == 1) {
#if defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
#else
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(fd, &read_fds);
                timeval timeout;
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;

                const int select_rc = select(fd + 1, &read_fds, NULL, NULL, &timeout);
                if (select_rc < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    std::cerr << "select failed: " << errno << '\n';
                    break;
                }
                if (select_rc == 0) {
                    continue;
                }
#endif
#if defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
                // Select is intentionally unsupported on Windows in this example.
                // Keep the loop alive by using a short timed wait.
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
#endif
            } else if (ready_mode == 2 && event_handle != nullptr) {
#if defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
                const DWORD wait_rc = WaitForSingleObject((HANDLE)event_handle, 1000);
                if (wait_rc == WAIT_TIMEOUT) {
                    continue;
                }
                if (wait_rc != WAIT_OBJECT_0) {
                    std::cerr << "WaitForSingleObject failed: " << GetLastError() << '\n';
                    break;
                }
#else
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
#endif
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        const int rc = zpcap_next_ex(handle, &hdr, &pkt);
        if (rc == 1) {
            ++handled;
            std::cout << "[#" << handled << "] ts="
                      << hdr->ts.tv_sec << '.' << hdr->ts.tv_usec
                      << " caplen=" << hdr->caplen
                      << " len=" << hdr->len << '\n';
            continue;
        }

        if (rc == -2) {
            std::cout << "End of capture after " << handled << " packets.\n";
            break;
        }

        if (rc == 0) {
            continue;
        }

        std::cerr << "next_ex returned error code: " << rc << '\n';
        break;
    }

    if (use_live) {
        zpcap_stat_t st;
        if (zpcap_stats(handle, &st) == 0) {
            std::cout << "stats: ps_recv=" << st.ps_recv
                      << " ps_drop=" << st.ps_drop
                      << " ps_ifdrop=" << st.ps_ifdrop << '\n';
        }
    }

    std::cout << "Loop finished after " << iterations
              << " iterations, handled=" << handled << '\n';
    zpcap_close(handle);
    return 0;
}
