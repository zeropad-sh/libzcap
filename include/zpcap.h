#ifndef ZPCAP_H
#define ZPCAP_H

#include <stdint.h>

#ifdef _WIN32
    #define ZPCAP_API __declspec(dllexport)
#else
    #define ZPCAP_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zpcap zpcap_t;

struct timeval_z {
    int32_t tv_sec;
    int32_t tv_usec;
};

typedef struct {
    struct timeval_z ts;
    uint32_t caplen;
    uint32_t len;
} zpcap_pkthdr;

#define ZPCAP_ERRBUF_SIZE 256

ZPCAP_API zpcap_t *zpcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
ZPCAP_API const uint8_t *zpcap_next(zpcap_t *p, zpcap_pkthdr *h);
ZPCAP_API void zpcap_close(zpcap_t *p);
ZPCAP_API const char *zpcap_geterr(zpcap_t *p);
ZPCAP_API int zpcap_datalink(zpcap_t *p);

typedef void (*zpcap_handler)(uint8_t *user, const zpcap_pkthdr *h, const uint8_t *bytes);
ZPCAP_API int zpcap_loop(zpcap_t *p, int cnt, zpcap_handler callback, uint8_t *user);

typedef struct zpcap_dumper zpcap_dumper_t;
ZPCAP_API zpcap_dumper_t *zpcap_dump_open(zpcap_t *p, const char *fname);
ZPCAP_API void zpcap_dump(uint8_t *user, const zpcap_pkthdr *h, const uint8_t *sp);
ZPCAP_API void zpcap_dump_close(zpcap_dumper_t *p);

#ifdef __cplusplus
}
#endif

#endif /* ZPCAP_H */
