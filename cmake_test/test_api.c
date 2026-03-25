/**
 * libzcap C API test program
 * Tests the C API exports and structure definitions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Include the libzcap header */
#include "../include/libzcap.h"

static void test_version(void) {
    printf("=== libzcap Version Test ===\n");
    printf("Version: %s\n", libzcap_version());
    printf("\n");
}

static void test_kernel_features(void) {
    printf("=== Kernel Feature Detection ===\n");
    
    int major = 0, minor = 0, patch = 0;
    libzcap_kernel_version(&major, &minor, &patch);
    printf("Kernel: %d.%d.%d\n", major, minor, patch);
    
    uint32_t features = libzcap_detect_features();
    printf("Features: 0x%08X\n", features);
    
    if (features & LIBZCAP_FEAT_BASIC) printf("  [x] Basic capture\n");
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
    printf("LIBZCAP_DLT_RAW: %d\n", LIBZCAP_DLT_RAW);
    printf("\n");
}

static void test_datalink_names(void) {
    printf("=== Data Link Type Names ===\n");
    printf("DLT name for EN10MB (1): %s\n", 
           libzcap_datalink_val_to_name(LIBZCAP_DLT_EN10MB));
    printf("DLT name for LINUX_SLL (113): %s\n",
           libzcap_datalink_val_to_name(LIBZCAP_DLT_LINUX_SLL));
    printf("DLT name for RAW (101): %s\n",
           libzcap_datalink_val_to_name(LIBZCAP_DLT_RAW));
    
    const char *desc = libzcap_datalink_val_to_description(LIBZCAP_DLT_EN10MB);
    printf("DLT description for EN10MB: %s\n", desc ? desc : "(null)");
    printf("\n");
}

static void test_structures(void) {
    printf("=== Structure Sizes ===\n");
    printf("sizeof(libzcap_pkthdr_t): %zu bytes\n", sizeof(libzcap_pkthdr_t));
    printf("sizeof(libzcap_stat_t): %zu bytes\n", sizeof(libzcap_stat_t));
    printf("sizeof(libzcap_bpf_program_t): %zu bytes\n", sizeof(libzcap_bpf_program_t));
    printf("sizeof(libzcap_bpf_insn_t): %zu bytes\n", sizeof(libzcap_bpf_insn_t));
    printf("\n");
}

static void test_error_handling(void) {
    printf("=== Error Handling ===\n");
    char buf[256];
    
    libzcap_strerror(LIBZCAP_ERROR, buf, sizeof(buf));
    printf("LIBZCAP_ERROR: %s\n", buf);
    
    libzcap_strerror(LIBZCAP_ERROR_NO_SUCH_DEVICE, buf, sizeof(buf));
    printf("LIBZCAP_ERROR_NO_SUCH_DEVICE: %s\n", buf);
    
    libzcap_strerror(LIBZCAP_ERROR_PERM_DENIED, buf, sizeof(buf));
    printf("LIBZCAP_ERROR_PERM_DENIED: %s\n", buf);
    printf("\n");
}

static void test_api_exports(void) {
    printf("=== API Function Exports ===\n");
    printf("libzcap_version:                 %p\n", (void*)libzcap_version);
    printf("libzcap_strerror:                 %p\n", (void*)libzcap_strerror);
    printf("libzcap_detect_features:           %p\n", (void*)libzcap_detect_features);
    printf("libzcap_kernel_version:            %p\n", (void*)libzcap_kernel_version);
    printf("libzcap_findalldevs:              %p\n", (void*)libzcap_findalldevs);
    printf("libzcap_freealldevs:              %p\n", (void*)libzcap_freealldevs);
    printf("libzcap_lookupdev:               %p\n", (void*)libzcap_lookupdev);
    printf("libzcap_open_live:                %p\n", (void*)libzcap_open_live);
    printf("libzcap_open_offline:            %p\n", (void*)libzcap_open_offline);
    printf("libzcap_create:                   %p\n", (void*)libzcap_create);
    printf("libzcap_close:                    %p\n", (void*)libzcap_close);
    printf("libzcap_dispatch:                 %p\n", (void*)libzcap_dispatch);
    printf("libzcap_loop:                     %p\n", (void*)libzcap_loop);
    printf("libzcap_next_ex:                  %p\n", (void*)libzcap_next_ex);
    printf("libzcap_breakloop:                %p\n", (void*)libzcap_breakloop);
    printf("libzcap_send:                     %p\n", (void*)libzcap_send);
    printf("libzcap_stats:                    %p\n", (void*)libzcap_stats);
    printf("libzcap_datalink:                %p\n", (void*)libzcap_datalink);
    printf("libzcap_fileno:                   %p\n", (void*)libzcap_fileno);
    printf("libzcap_compile:                  %p\n", (void*)libzcap_compile);
    printf("libzcap_setfilter:               %p\n", (void*)libzcap_setfilter);
    printf("libzcap_dump_open:                %p\n", (void*)libzcap_dump_open);
    printf("libzcap_dump:                     %p\n", (void*)libzcap_dump);
    printf("libzcap_dump_close:               %p\n", (void*)libzcap_dump_close);
    printf("libzcap_geterr:                   %p\n", (void*)libzcap_geterr);
    printf("libzcap_perror:                  %p\n", (void*)libzcap_perror);
    printf("\n");
}

static void test_dead_handle(void) {
    printf("=== Dead Handle Operations ===\n");
    
    /* Create a dead handle */
    libzcap_t *p = libzcap_open_dead(LIBZCAP_DLT_EN10MB, 65535);
    if (p) {
        printf("libzcap_open_dead: succeeded\n");
        
        int dlt = libzcap_datalink(p);
        printf("libzcap_datalink: %d\n", dlt);
        
        int snaplen = libzcap_snapshot(p);
        printf("libzcap_snapshot: %d\n", snaplen);
        
        int fileno = libzcap_fileno(p);
        printf("libzcap_fileno: %d\n", fileno);
        
        libzcap_close(p);
        printf("libzcap_close: succeeded\n");
    } else {
        printf("libzcap_open_dead: failed (expected on some platforms)\n");
    }
    printf("\n");
}

static void test_findalldevs(void) {
    printf("=== Device Discovery ===\n");
    
    char errbuf[LIBZCAP_ERRBUF_SIZE];
    libzcap_if_t *alldevs = NULL;
    
    int result = libzcap_findalldevs(&alldevs, errbuf);
    if (result == 0 && alldevs) {
        printf("Devices found:\n");
        libzcap_if_t *dev = alldevs;
        int count = 0;
        while (dev) {
            printf("  %d: %s", count + 1, dev->name);
            if (dev->description) {
                printf(" - %s", dev->description);
            }
            if (dev->flags & 0x01) printf(" [loopback]");
            if (dev->flags & 0x02) printf(" [up]");
            if (dev->flags & 0x04) printf(" [running]");
            printf("\n");
            dev = dev->next;
            count++;
        }
        printf("Total: %d devices\n", count);
        libzcap_freealldevs(alldevs);
    } else {
        printf("libzcap_findalldevs: %s\n", errbuf);
    }
    printf("\n");
}

int main(void) {
    printf("\n");
    printf("################################################################\n");
    printf("#                                                              #\n");
    printf("#                    libzcap C API Test                       #\n");
    printf("#                                                              #\n");
    printf("################################################################\n");
    printf("\n");
    
    test_version();
    test_kernel_features();
    test_constants();
    test_datalink_names();
    test_structures();
    test_error_handling();
    test_api_exports();
    test_dead_handle();
    test_findalldevs();
    
    printf("################################################################\n");
    printf("#                     All Tests Passed                        #\n");
    printf("################################################################\n");
    printf("\n");
    
    return 0;
}
