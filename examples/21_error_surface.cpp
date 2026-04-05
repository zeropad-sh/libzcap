#include <cinttypes>
#include <cstdint>
#include <iostream>
#include <zpcap.h>

static void on_packet(uint8_t *user, const zpcap_pkthdr *hdr, const uint8_t *pkt) {
    (void)pkt;

    uint64_t *count = reinterpret_cast<uint64_t *>(user);
    ++(*count);

    if (*count <= 2) {
        std::cout << "dispatch packet=" << *count
                  << " caplen=" << hdr->caplen
                  << " len=" << hdr->len << '\n';
    }
}

int main(int argc, char **argv) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    const char *path = (argc > 1) ? argv[1] : "tests/sample.pcap";

    std::cout << "zpcap_lib_version: " << zpcap_lib_version() << '\n';
    std::cout << "zpcap_strerror invalid arg: " << zpcap_strerror(ZPCAP_ERROR_INVALID_ARGUMENT) << '\n';
    std::cout << "zpcap_strerror i/o: " << zpcap_strerror(ZPCAP_ERROR_IO) << '\n';

    zpcap_t *probe = zpcap_open_offline("this-file-does-not-exist.pcap", errbuf);
    if (probe != NULL) {
        zpcap_close(probe);
        std::cerr << "unexpectedly opened missing file\n";
        return 1;
    }
    zpcap_perror(NULL, "missing-file open");

    zpcap_t *handle = zpcap_open_offline(path, errbuf);
    if (handle == NULL) {
        std::cerr << "zpcap_open_offline failed: " << errbuf << '\n';
        return 1;
    }

    if (zpcap_setnonblock(handle, 2, errbuf) != 0) {
        std::cout << "expected setnonblock failure: " << errbuf << '\n';
        zpcap_perror(handle, "invalid nonblock");
    } else {
        std::cout << "unexpected setnonblock return value\n";
        zpcap_close(handle);
        return 1;
    }

    uint64_t packet_count = 0;
    const int rc = zpcap_dispatch(handle, -1, on_packet, reinterpret_cast<uint8_t *>(&packet_count));
    std::cout << "zpcap_dispatch returned=" << rc << '\n';
    std::cout << "dispatch packets: " << packet_count << '\n';
    if (rc < 0) {
        zpcap_perror(handle, "dispatch");
        zpcap_close(handle);
        return 1;
    }

    zpcap_close(handle);
    return 0;
}
