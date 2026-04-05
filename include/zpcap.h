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

#define ZPCAP_BUFFER_MODE_COPY 0
#define ZPCAP_BUFFER_MODE_RING_MMAP 1

#define ZPCAP_ERROR_OK 0
#define ZPCAP_ERROR_NO_MEMORY 100
#define ZPCAP_ERROR_INVALID_ARGUMENT 101
#define ZPCAP_ERROR_NOT_ACTIVATED 102
#define ZPCAP_ERROR_NO_SUCH_DEVICE 103
#define ZPCAP_ERROR_PERM_DENIED 104
#define ZPCAP_ERROR_UNSUPPORTED 105
#define ZPCAP_ERROR_BUSY 106
#define ZPCAP_ERROR_TIMEOUT 107
#define ZPCAP_ERROR_NOT_IMPLEMENTED 108
#define ZPCAP_ERROR_IO 109
#define ZPCAP_ERROR_UNKNOWN 255

#define ZPCAP_FANOUT_NONE 255
#define ZPCAP_FANOUT_HASH 0
#define ZPCAP_FANOUT_LB 1
#define ZPCAP_FANOUT_CPU 2
#define ZPCAP_FANOUT_RANDOM 3
#define ZPCAP_FANOUT_ROLLOVER 4
#define ZPCAP_FANOUT_CBPF 5
#define ZPCAP_FANOUT_EBPF 6

#define ZPCAP_FEATURE_BASIC 0x01
#define ZPCAP_FEATURE_RING_V3 0x02
#define ZPCAP_FEATURE_EBPF 0x04
#define ZPCAP_FEATURE_HW_TSTAMP 0x08
#define ZPCAP_FEATURE_AF_XDP 0x10
#define ZPCAP_FEATURE_FANOUT 0x20
#define ZPCAP_FEATURE_BUSY_POLL 0x40
 
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

typedef struct {
    uint32_t version;
    uint32_t buffer_mode;
    uint32_t ring_block_size;
    uint32_t ring_block_count;
    uint32_t ring_frame_size;
    uint32_t ring_frame_count;
    uint32_t fanout_mode;
    uint16_t fanout_group;
    uint32_t busy_poll_usec;
    int32_t fallback_to_copy;
} zpcap_open_options;

ZPCAP_API zpcap_t *zpcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
ZPCAP_API zpcap_t *zpcap_open_live_ex(
    const char *device,
    int snaplen,
    int promisc,
    int to_ms,
    const zpcap_open_options *options,
    char *errbuf
);
ZPCAP_API const uint8_t *zpcap_next(zpcap_t *p, zpcap_pkthdr *h);
ZPCAP_API void zpcap_close(zpcap_t *p);
ZPCAP_API const char *zpcap_lib_version(void);
ZPCAP_API const char *zpcap_strerror(int errnum);
ZPCAP_API void zpcap_perror(zpcap_t *p, const char *prefix);
ZPCAP_API const char *zpcap_geterr(zpcap_t *p);
ZPCAP_API int zpcap_geterrnum(zpcap_t *p);
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
ZPCAP_API int zpcap_dump_flush(zpcap_dumper_t *p);
ZPCAP_API void zpcap_dump_close(zpcap_dumper_t *p);
ZPCAP_API int zpcap_sendpacket(zpcap_t *p, const uint8_t *buf, int len);
ZPCAP_API int zpcap_send(zpcap_t *p, const uint8_t *buf, int len);
ZPCAP_API int zpcap_getnonblock(zpcap_t *p, char *errbuf);
ZPCAP_API int zpcap_get_buffer_mode(zpcap_t *p);
ZPCAP_API int zpcap_setnonblock(zpcap_t *p, int nonblock, char *errbuf);
ZPCAP_API int zpcap_stats(zpcap_t *p, zpcap_stat_t *stats);
ZPCAP_API int zpcap_get_selectable_fd(zpcap_t *p);
ZPCAP_API void *zpcap_getevent(zpcap_t *p);

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
ZPCAP_API uint32_t zpcap_detect_features(void);
ZPCAP_API int zpcap_kernel_version(int *major, int *minor, int *patch);

#ifdef __cplusplus
}
#endif

#endif /* ZPCAP_H */
