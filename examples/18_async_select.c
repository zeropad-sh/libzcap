#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <zpcap.h>

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
    while (handled < max_packets) {
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
                struct timeval timeout = {0, 10 * 1000};
                select(0, NULL, NULL, NULL, &timeout);
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
