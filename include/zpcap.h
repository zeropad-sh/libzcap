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
#define ZPCAP_NETMASK_UNKNOWN 0xffffffff
 
typedef struct zpcap_if {
    struct zpcap_if *next;
    char *name;
    char *description;
    void *addresses;
    uint32_t flags;
} zpcap_if_t;

typedef struct {
    uint32_t ps_recv;
    uint32_t ps_drop;
    uint32_t ps_ifdrop;
} zpcap_stat_t;

ZPCAP_API zpcap_t *zpcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
ZPCAP_API const uint8_t *zpcap_next(zpcap_t *p, zpcap_pkthdr *h);
ZPCAP_API void zpcap_close(zpcap_t *p);
ZPCAP_API const char *zpcap_geterr(zpcap_t *p);
ZPCAP_API int zpcap_datalink(zpcap_t *p);
ZPCAP_API int zpcap_findalldevs(zpcap_if_t **alldevs, char *errbuf);
ZPCAP_API void zpcap_freealldevs(zpcap_if_t *alldevs);
ZPCAP_API const char *zpcap_lookupdev(char *errbuf);

typedef void (*zpcap_handler)(uint8_t *user, const zpcap_pkthdr *h, const uint8_t *bytes);
ZPCAP_API int zpcap_loop(zpcap_t *p, int cnt, zpcap_handler callback, uint8_t *user);
ZPCAP_API int zpcap_dispatch(zpcap_t *p, int cnt, zpcap_handler callback, uint8_t *user);
ZPCAP_API int zpcap_next_ex(zpcap_t *p, zpcap_pkthdr **hdr, const uint8_t **pkt);
ZPCAP_API void zpcap_breakloop(zpcap_t *p);

typedef struct zpcap_dumper zpcap_dumper_t;
ZPCAP_API zpcap_dumper_t *zpcap_dump_open(zpcap_t *p, const char *fname);
ZPCAP_API void zpcap_dump(uint8_t *user, const zpcap_pkthdr *h, const uint8_t *sp);
ZPCAP_API void zpcap_dump_close(zpcap_dumper_t *p);
ZPCAP_API int zpcap_sendpacket(zpcap_t *p, const uint8_t *buf, int len);
ZPCAP_API int zpcap_send(zpcap_t *p, const uint8_t *buf, int len);
ZPCAP_API int zpcap_getnonblock(zpcap_t *p, char *errbuf);
ZPCAP_API int zpcap_setnonblock(zpcap_t *p, int nonblock, char *errbuf);
ZPCAP_API int zpcap_stats(zpcap_t *p, zpcap_stat_t *stats);
ZPCAP_API int zpcap_get_selectable_fd(zpcap_t *p);

struct zpcap_bpf_insn {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

struct zpcap_bpf_program {
    uint32_t bf_len;
    struct zpcap_bpf_insn *bf_insns;
};

ZPCAP_API zpcap_t *zpcap_open_offline(const char *fname, char *errbuf);
ZPCAP_API int zpcap_compile(zpcap_t *p, struct zpcap_bpf_program *fp, const char *str, int optimize, uint32_t netmask);
ZPCAP_API int zpcap_setfilter(zpcap_t *p, struct zpcap_bpf_program *fp);
ZPCAP_API void zpcap_freecode(struct zpcap_bpf_program *fp);

#ifdef __cplusplus
}
#endif

#endif /* ZPCAP_H */
