# C99 Example: Find Devices and Default Device

This example shows the `zpcap_findalldevs` and `zpcap_lookupdev` APIs.

## Source (`examples/11_findalldevs_lookupdev.c`)

```c
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
```

## Build and run

```bash
zig build
gcc -std=c99 -o docs/examples/c99-find-devices \
  examples/11_findalldevs_lookupdev.c -Iinclude -Lzig-out/lib -lzcap
./docs/examples/c99-find-devices
```

## What this shows

- `zpcap_findalldevs` returns a linked list of discovered devices.
- `zpcap_lookupdev` returns one default interface name.
- `zpcap_freealldevs` must always be called on the list.
