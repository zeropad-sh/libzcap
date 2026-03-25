/**
 * libzcap C API stub implementation
 * For testing header compilation without linking
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../include/libzcap.h"

/* Stub implementations for testing */
const char * libzcap_version_string(void) {
    return "0.1.0-stub";
}

void libzcap_version(int *major, int *minor, int *patch) {
    if (major) *major = 0;
    if (minor) *minor = 1;
    if (patch) *patch = 0;
}

uint32_t libzcap_detect_features(void) {
    return LIBZCAP_FEAT_BASIC | LIBZCAP_FEAT_RING_V3;
}

int libzcap_kernel_version_major(void) { return 5; }
int libzcap_kernel_version_minor(void) { return 15; }
int libzcap_kernel_version_patch(void) { return 0; }

libzcap_t * libzcap_open(const libzcap_options_t *options) {
    (void)options;
    return NULL;
}

libzcap_error_t libzcap_close(libzcap_t *handle) {
    (void)handle;
    return LIBZCAP_SUCCESS;
}

const libzcap_packet_header_t * libzcap_next(libzcap_t *handle, const uint8_t **data) {
    (void)handle;
    (void)data;
    return NULL;
}

int libzcap_loop(libzcap_t *handle, int count, libzcap_callback_fn callback, void *user) {
    (void)handle;
    (void)count;
    (void)callback;
    (void)user;
    return 0;
}

void libzcap_breakloop(libzcap_t *handle) {
    (void)handle;
}

libzcap_error_t libzcap_stats(libzcap_t *handle, libzcap_stats_t *stats) {
    (void)handle;
    if (stats) memset(stats, 0, sizeof(*stats));
    return LIBZCAP_SUCCESS;
}

libzcap_t * libzcap_pcap_open_live(const char *device, int snaplen, 
                                    int promisc, int to_ms, char *errbuf) {
    (void)device;
    (void)snaplen;
    (void)promisc;
    (void)to_ms;
    if (errbuf) strcpy(errbuf, "Not implemented");
    return NULL;
}

void libzcap_pcap_close(libzcap_t *p) {
    (void)p;
}

const uint8_t * libzcap_pcap_next(libzcap_t *p, libzcap_packet_header_t *hdr) {
    (void)p;
    (void)hdr;
    return NULL;
}

int libzcap_pcap_datalink(libzcap_t *p) {
    (void)p;
    return LIBZCAP_DLT_EN10MB;
}

const char * libzcap_pcap_geterr(libzcap_t *p) {
    (void)p;
    return "Not implemented";
}

int libzcap_compile_filter(const char *filter_expr, int optimize,
                           uint32_t netmask, libzcap_bpf_program_t *program) {
    (void)filter_expr;
    (void)optimize;
    (void)netmask;
    if (program) {
        program->bf_len = 0;
        program->bf_insns = NULL;
    }
    return -1;
}

void libzcap_free_filter(libzcap_bpf_program_t *program) {
    (void)program;
}

libzcap_error_t libzcap_setfilter(libzcap_t *handle, const libzcap_bpf_program_t *program) {
    (void)handle;
    (void)program;
    return LIBZCAP_ERROR_NOT_SUPPORTED;
}
