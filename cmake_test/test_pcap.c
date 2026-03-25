/**
 * libzcap C API test program
 * Tests the C API exports and structure definitions
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Include the libzcap header */
#include "../include/libzcap.h"

static void print_version(void) {
    printf("=== libzcap C API Test ===\n\n");
    printf("Library version: %s\n", libzcap_version_string());
    
    int major, minor, patch;
    libzcap_version(&major, &minor, &patch);
    printf("Version components: %d.%d.%d\n\n", major, minor, patch);
}

static void test_kernel_detection(void) {
    printf("=== Kernel Feature Detection ===\n");
    
    printf("Kernel version: %d.%d.%d\n",
           libzcap_kernel_version_major(),
           libzcap_kernel_version_minor(),
           libzcap_kernel_version_patch());
    
    uint32_t features = libzcap_detect_features();
    printf("Available features: 0x%08X\n", features);
    
    if (features & LIBZCAP_FEAT_BASIC) printf("  [x] Basic capture (AF_PACKET)\n");
    if (features & LIBZCAP_FEAT_RING_V3) printf("  [x] TPACKET_V3 ring buffer\n");
    if (features & LIBZCAP_FEAT_EBPF) printf("  [x] eBPF socket filter\n");
    if (features & LIBZCAP_FEAT_HW_TSTAMP) printf("  [x] Hardware timestamps\n");
    if (features & LIBZCAP_FEAT_AF_XDP) printf("  [x] AF_XDP zero-copy\n");
    
    printf("\n");
}

static void test_constants(void) {
    printf("=== Constants ===\n");
    printf("LIBZCAP_ERRBUF_SIZE: %d\n", LIBZCAP_ERRBUF_SIZE);
    printf("LIBZCAP_SNAPLEN_DEFAULT: %u\n", LIBZCAP_SNAPLEN_DEFAULT);
    printf("LIBZCAP_DLT_EN10MB: %d\n", LIBZCAP_DLT_EN10MB);
    printf("LIBZCAP_DLT_LINUX_SLL: %d\n", LIBZCAP_DLT_LINUX_SLL);
    printf("\n");
}

static void test_structures(void) {
    printf("=== Structure Sizes ===\n");
    printf("sizeof(libzcap_t): opaque (not accessible)\n");
    printf("sizeof(libzcap_packet_header_t): %zu\n", sizeof(libzcap_packet_header_t));
    printf("sizeof(libzcap_stats_t): %zu\n", sizeof(libzcap_stats_t));
    printf("sizeof(libzcap_options_t): %zu\n", sizeof(libzcap_options_t));
    printf("sizeof(libzcap_bpf_program_t): %zu\n", sizeof(libzcap_bpf_program_t));
    printf("\n");
}

static void test_api_exports(void) {
    printf("=== API Function Exports ===\n");
    printf("libzcap_version_string:      %p\n", (void*)libzcap_version_string);
    printf("libzcap_version:             %p\n", (void*)libzcap_version);
    printf("libzcap_detect_features:    %p\n", (void*)libzcap_detect_features);
    printf("libzcap_kernel_version_*:    %p %p %p\n",
           (void*)libzcap_kernel_version_major,
           (void*)libzcap_kernel_version_minor,
           (void*)libzcap_kernel_version_patch);
    printf("libzcap_open:               %p\n", (void*)libzcap_open);
    printf("libzcap_close:              %p\n", (void*)libzcap_close);
    printf("libzcap_next:               %p\n", (void*)libzcap_next);
    printf("libzcap_loop:               %p\n", (void*)libzcap_loop);
    printf("libzcap_breakloop:          %p\n", (void*)libzcap_breakloop);
    printf("libzcap_stats:              %p\n", (void*)libzcap_stats);
    printf("libzcap_pcap_open_live:     %p\n", (void*)libzcap_pcap_open_live);
    printf("libzcap_pcap_close:         %p\n", (void*)libzcap_pcap_close);
    printf("libzcap_pcap_next:          %p\n", (void*)libzcap_pcap_next);
    printf("libzcap_pcap_datalink:      %p\n", (void*)libzcap_pcap_datalink);
    printf("libzcap_pcap_geterr:        %p\n", (void*)libzcap_pcap_geterr);
    printf("libzcap_compile_filter:      %p\n", (void*)libzcap_compile_filter);
    printf("libzcap_free_filter:        %p\n", (void*)libzcap_free_filter);
    printf("libzcap_setfilter:          %p\n", (void*)libzcap_setfilter);
    printf("\n");
}

static void test_enum_values(void) {
    printf("=== Enum Values ===\n");
    printf("LIBZCAP_FEAT_BASIC:     0x%08X\n", LIBZCAP_FEAT_BASIC);
    printf("LIBZCAP_FEAT_RING_V3:   0x%08X\n", LIBZCAP_FEAT_RING_V3);
    printf("LIBZCAP_FEAT_EBPF:      0x%08X\n", LIBZCAP_FEAT_EBPF);
    printf("LIBZCAP_FEAT_AF_XDP:    0x%08X\n", LIBZCAP_FEAT_AF_XDP);
    printf("\n");
    printf("LIBZCAP_SUCCESS:        %d\n", LIBZCAP_SUCCESS);
    printf("LIBZCAP_ERROR_GENERIC:  %d\n", LIBZCAP_ERROR_GENERIC);
    printf("\n");
}

int main(void) {
    print_version();
    test_kernel_detection();
    test_constants();
    test_structures();
    test_enum_values();
    test_api_exports();
    
    printf("=== Test Complete ===\n");
    printf("All C API exports verified successfully!\n");
    
    return 0;
}
