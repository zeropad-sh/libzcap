#include <stdio.h>
#include <stdlib.h>
#include <zpcap.h>

int main(void) {
    char errbuf[ZPCAP_ERRBUF_SIZE];
    zpcap_if_t *all = NULL;

    if (zpcap_findalldevs(&all, errbuf) != 0) {
        fprintf(stderr, "findalldevs failed: %s\n", errbuf);
        return 1;
    }

    printf("Devices returned by zpcap_findalldevs:\n");
    for (zpcap_if_t *dev = all; dev != NULL; dev = dev->next) {
        if (dev->name != NULL) {
            printf("  - %s\n", dev->name);
        }
    }

    const char *default_dev = zpcap_lookupdev(errbuf);
    if (default_dev == NULL) {
        fprintf(stderr, "lookupdev failed: %s\n", errbuf);
    } else {
        printf("Default device from zpcap_lookupdev: %s\n", default_dev);
    }

    zpcap_freealldevs(all);
    return 0;
}
