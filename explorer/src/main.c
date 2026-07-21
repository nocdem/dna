/* dna-explorerd — read-only DNAC chain indexer + JSON API (scan.cpunk.io) */
#include <stdio.h>
#include <string.h>
#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXPLORER"

#define EXPLORERD_VERSION "0.1.0"

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("dna-explorerd %s\n", EXPLORERD_VERSION);
        return 0;
    }
    QGP_LOG_INFO(LOG_TAG, "dna-explorerd %s starting", EXPLORERD_VERSION);
    return 0;
}
