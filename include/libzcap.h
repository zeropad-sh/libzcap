/**
 * libzcap - Zero-copy, high-performance packet capture library
 * Modern C API - Fully documented native interface
 */

#ifndef LIBZCAP_H
#define LIBZCAP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <time.h>
    #define LIBZCAP_API __declspec(dllexport)
    #define LIBZCAP_CALL __cdecl
#else
    #include <sys/time.h>
    #include <stdio.h>
    #define LIBZCAP_API
    #define LIBZCAP_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Semantic Version Constants */
#define LIBZCAP_VERSION_MAJOR 0
#define LIBZCAP_VERSION_MINOR 1
#define LIBZCAP_VERSION_PATCH 0

/* Standard buffer sizing */
#define LIBZCAP_ERRBUF_SIZE 256
#define LIBZCAP_SNAPLEN_DEFAULT 65535
#define LIBZCAP_NETMASK_UNKNOWN 0xffffffff

/**
 * @brief Data Link Types representing the physical topology of the capture interface.
 * Matches standard libpcap DLT_ specifications.
 */
typedef enum {
    LIBZCAP_DLT_NULL = 0,
    LIBZCAP_DLT_EN10MB = 1,
    LIBZCAP_DLT_RAW = 101,
    LIBZCAP_DLT_IEEE802_11 = 105,
    LIBZCAP_DLT_LOOP = 108,
    LIBZCAP_DLT_LINUX_SLL = 113,
    LIBZCAP_DLT_IEEE802_11_RADIO = 127,
    LIBZCAP_DLT_IPV4 = 228,
    LIBZCAP_DLT_IPV6 = 229,
    LIBZCAP_DLT_PPP_SERIAL = 50,
    LIBZCAP_DLT_PPP_ETHER = 204,
    LIBZCAP_DLT_SOCKET_CAN = 227,
    LIBZCAP_DLT_NETANALYZER = 12,
    LIBZCAP_DLT_NETANALYZER_TRANSPARENT = 15,
    LIBZCAP_DLT_SCTP = 248,
} libzcap_dlt_t;

/**
 * @brief Determines the directional filtering of the capture listener.
 */
typedef enum {
    LIBZCAP_D_INOUT = 0, /* Capture all traffic on interface */
    LIBZCAP_D_IN = 1,    /* Capture ingress traffic only */
    LIBZCAP_D_OUT = 2,   /* Capture egress traffic only */
} libzcap_direction_t;

/**
 * @brief Standardized exit codes representing distinct error conditions.
 */
typedef enum {
    LIBZCAP_ERROR = -1,
    LIBZCAP_ERROR_BREAK = -2,
    LIBZCAP_ERROR_NOT_ACTIVATED = -3,
    LIBZCAP_ERROR_NO_SUCH_DEVICE = -5,
    LIBZCAP_ERROR_PERM_DENIED = -8,
} libzcap_error_t;

/* Feature detection mappings indicating compile-time OS support. */
#define LIBZCAP_FEAT_BASIC     0x01
#define LIBZCAP_FEAT_RING_V3  0x02
#define LIBZCAP_FEAT_EBPF      0x04
#define LIBZCAP_FEAT_HW_TSTAMP 0x08
#define LIBZCAP_FEAT_AF_XDP   0x10

/** @brief Opaque abstraction shielding the execution context over the OS backend loop. */
struct libzcap;
typedef struct libzcap libzcap_t;

/** @brief Opaque descriptor representing an active pcap file writing stream. */
struct libzcap_dumper;
typedef struct libzcap_dumper libzcap_dumper_t;

/**
 * @brief Header metadata parsed strictly alongside the yielded binary buffer of every network frame.
 */
typedef struct {
    struct timeval ts;  /* Ingress OS hardware/software timestamp */
    uint32_t caplen;    /* Sliced or truncated frame length present in memory */
    uint32_t len;       /* Total frame length strictly parsed off the wire */
} libzcap_pkthdr_t;

/**
 * @brief Zero-copy metrics recording hardware frame resolutions.
 */
typedef struct {
    uint32_t ps_recv;   /* Valid packets consumed from interface space */
    uint32_t ps_drop;   /* Packets discarded locally traversing ring blocks */
    uint32_t ps_ifdrop; /* Packets discarded natively across interface hardware limit constraints */
} libzcap_stat_t;

/* BPF Program and Instruction Mapping Types representing Berkeley Packet Filter syntax trees */
typedef struct {
    uint32_t len;
    void *insns;
} libzcap_bpf_program_t;

typedef struct {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
} libzcap_bpf_insn_t;

/**
 * @brief Asynchronous execution sink parsing individual packet outputs looping iteratively over libzcap loops.
 * 
 * @param user Custom user pointer provided to the loop sequence
 * @param hdr Frame header representation
 * @param data Raw byte array representing the captured data slice
 */
typedef void (LIBZCAP_CALL *libzcap_handler_cb)(
    uint8_t *user,
    const libzcap_pkthdr_t *hdr,
    const uint8_t *data
);

/**
 * @brief Linked-list entry of available network adapter targets strictly found locally for capture selection.
 */
typedef struct libzcap_if {
    struct libzcap_if *next;
    char *name;
    char *description;
    void *addresses;
    uint32_t flags;
} libzcap_if_t;

/*============================================================================
 * Core API Initialization
 *============================================================================*/

/**
 * @brief Evaluates compile time library version bounds.
 * @return String representing semantic format (e.g. "0.1.0")
 */
LIBZCAP_API const char * LIBZCAP_CALL libzcap_version(void);

/**
 * @brief Returns system string details translating an error enum.
 */
LIBZCAP_API int libzcap_strerror(int errnum, char *buf, size_t buflen);

/** @brief Generates bitmask detecting native advanced OS backend bindings available to libzcap */
LIBZCAP_API uint32_t libzcap_detect_features(void);
LIBZCAP_API int libzcap_kernel_version(int *major, int *minor, int *patch);

/**
 * @brief Probes all underlying local loopback and ethernet network adaptors explicitly supporting capture.
 * @param alldevs Address pointer populating the constructed linked list graph of libzcap_if_t outputs
 * @param errbuf Output array mapping any failure details evaluated
 */
LIBZCAP_API int libzcap_findalldevs(libzcap_if_t **alldevs, char *errbuf);

/** @brief Memory cleanup destroying the populated adapter linked list after analysis */
LIBZCAP_API void libzcap_freealldevs(libzcap_if_t *alldevs);

/** @brief Returns default valid capture device name resolving basic target selections. */
LIBZCAP_API char * libzcap_lookupdev(char *errbuf);
LIBZCAP_API int libzcap_lookupnet(const char *device, uint32_t *netp, uint32_t *maskp, char *errbuf);

/**
 * @brief Directly opens and provisions a live raw capture hardware channel binding to the specified native OS endpoint.
 * 
 * @param device Target interface alias or guid
 * @param snaplen Expected truncated bounding box to force dropping memory bloat on larger transmissions.
 * @param promisc Toggles listening capability into adjacent subnet routing rather than interface explicitly constrained flows.
 * @param to_ms Frame delay tracking resolving interrupt batching over block yields within zero-copy mmap.
 * @param errbuf Diagnostic buffer receiving fatal error analysis.
 * @return Fully scoped libzcap_t handler pointer wrapping the activated execution stream. 
 */
LIBZCAP_API libzcap_t * libzcap_open_live(const char *device, int snaplen,
                                          int promisc, int to_ms, char *errbuf);

/** @brief Allocates an inactive packet parsing endpoint securely consuming offline standard PCAP files */
LIBZCAP_API libzcap_t * libzcap_open_offline(const char *fname, char *errbuf);

/** @brief Constructs an empty context simulating generic environments capable of utilizing injected pcap parsing operations */
LIBZCAP_API libzcap_t * libzcap_open_dead(int linktype, int snaplen);

/*============================================================================
 * Context State Parameterization
 *============================================================================*/

/** @brief Generates raw un-activated context demanding staged configuration. Requires consecutive activation. */
LIBZCAP_API libzcap_t * libzcap_create(const char *device, char *errbuf);

/** @brief Staged sizing parameter applying a snap execution slice limits during un-activated handles */
LIBZCAP_API int libzcap_set_snaplen(libzcap_t *p, int snaplen);

/** @brief Configures underlying un-activated socket contexts setting promiscuous network behavior bounds */
LIBZCAP_API int libzcap_set_promisc(libzcap_t *p, int promisc);

/** @brief Binds un-activated wait block buffer timeouts forcing poll completion thresholds */
LIBZCAP_API int libzcap_set_timeout(libzcap_t *p, int to_ms);

/** @brief Configures expected network ring block allocation sizes demanding internal native zero-copy alignments */
LIBZCAP_API int libzcap_set_buffer_size(libzcap_t *p, int size);

/** @brief Binds previously constructed generic un-activated endpoints to memory and fires hardware-level interception execution. */
LIBZCAP_API int libzcap_activate(libzcap_t *p);

/*============================================================================
 * Execution and Fetching Mechanisms
 *============================================================================*/

/**
 * @brief Terminates the active connection securely flushing mmap states and releasing file descriptors.
 */
LIBZCAP_API void libzcap_close(libzcap_t *p);

/**
 * @brief Synchronous execution iterating single un-blocked buffer packets across local handlers explicitly bypassing tight infinite loop routines.
 */
LIBZCAP_API int libzcap_dispatch(libzcap_t *p, int cnt, libzcap_handler_cb cb, uint8_t *user);

/**
 * @brief Implements an indefinitely looping hardware block consumption thread injecting each frame gracefully into caller-scoped callbacks.
 */
LIBZCAP_API int libzcap_loop(libzcap_t *p, int cnt, libzcap_handler_cb cb, uint8_t *user);

/**
 * @brief Iterative fetch extracting a pointer explicitly toward internal memory maps retaining zero-allocation limits efficiently binding header values natively.
 * @return 1 on Success, 0 on timeout.
 */
LIBZCAP_API int libzcap_next_ex(libzcap_t *p, libzcap_pkthdr_t **hdr, const uint8_t **data);

/**
 * @brief Secondary simplistic native extraction mapping values directly backwards to user memory states explicitly triggering block iterators.
 */
LIBZCAP_API const uint8_t * libzcap_next(libzcap_t *p, libzcap_pkthdr_t *hdr);

/** @brief Gracefully commands an infinite iterative libzcap_loop endpoint to cleanly cease processing frames */
LIBZCAP_API void libzcap_breakloop(libzcap_t *p);

/** @brief Transmits binary array arrays cleanly generating egress hardware injection explicitly via AF_PACKET layers */
LIBZCAP_API int libzcap_send(libzcap_t *p, const uint8_t *buf, int len);

/*============================================================================
 * Hardware Utilities
 *============================================================================*/

/** @brief Collects atomic thread-safe packet validation aggregates directly querying underlying ring buffer statistics */
LIBZCAP_API int libzcap_stats(libzcap_t *p, libzcap_stat_t *st);

/** @brief Native datalink mapping evaluating target physical OSI implementations resolving IEEE layers */
LIBZCAP_API int libzcap_datalink(libzcap_t *p);
LIBZCAP_API int libzcap_fileno(libzcap_t *p);
LIBZCAP_API FILE * libzcap_file(libzcap_t *p);

/*============================================================================
 * BPF Compilation Filtering
 *============================================================================*/

/** @brief Generates bytecode AST implementations routing custom BPF logic instructions toward the underlying socket */
LIBZCAP_API int libzcap_compile(libzcap_t *p, libzcap_bpf_program_t *prog,
                                const char *expr, int optimize, uint32_t netmask);
LIBZCAP_API void libzcap_freecode(libzcap_bpf_program_t *prog);

/** @brief Employs hardware-level filter validation demanding socket configurations apply specific BPF rules */
LIBZCAP_API int libzcap_setfilter(libzcap_t *p, const libzcap_bpf_program_t *prog);

/** @brief Narrows or broadens reception scope parsing strictly matching interface IN or OUT thresholds */
LIBZCAP_API int libzcap_setdirection(libzcap_t *p, libzcap_direction_t d);

LIBZCAP_API int libzcap_getnonblock(libzcap_t *p, char *errbuf);
LIBZCAP_API int libzcap_setnonblock(libzcap_t *p, int nonblock, char *errbuf);

/*============================================================================
 * Diagnostic Mapping
 *============================================================================*/

LIBZCAP_API const char * libzcap_geterr(libzcap_t *p);
LIBZCAP_API void libzcap_perror(libzcap_t *p, const char *prefix);

LIBZCAP_API int libzcap_datalink_name_to_val(const char *name);
LIBZCAP_API const char * libzcap_datalink_val_to_name(int dlt);
LIBZCAP_API const char * libzcap_datalink_val_to_description(int dlt);

/*============================================================================
 * File Dump API Output Integrations
 *============================================================================*/

/** @brief Generates file descriptor endpoints translating packets towards global magic pcap blocks natively */
LIBZCAP_API libzcap_dumper_t * libzcap_dump_open(libzcap_t *p, const char *fname);
LIBZCAP_API libzcap_dumper_t * libzcap_dump_open_append(libzcap_t *p, const char *fname);

/** @brief Forces a hard filesystem execution synchronizing mapped packet aggregations natively */
LIBZCAP_API int libzcap_dump_flush(libzcap_dumper_t *d);
LIBZCAP_API void libzcap_dump_close(libzcap_dumper_t *d);

/** @brief Pipes individual header blocks into the previously initialized libzcap_dumper_t writer sequence strictly */
LIBZCAP_API void libzcap_dump(libzcap_dumper_t *d, const libzcap_pkthdr_t *hdr, const uint8_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* LIBZCAP_H */
