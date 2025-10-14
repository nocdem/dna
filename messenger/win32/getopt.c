/*
 * getopt.c - POSIX getopt() and getopt_long() implementation for Windows
 *
 * This is a minimal, public domain implementation of POSIX getopt()
 * and getopt_long() for Windows compatibility.
 */

#include "getopt.h"
#include <string.h>
#include <stdio.h>

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = 0;

static char *nextchar = NULL;

int getopt(int argc, char * const argv[], const char *optstring) {
    static int sp = 1;
    int c;
    const char *cp;

    if (sp == 1) {
        /* Check for end of options */
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
            return -1;
        }

        /* Handle "--" end of options marker */
        if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }

    optopt = c = argv[optind][sp];

    /* Check for invalid option character */
    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (opterr && *optstring != ':') {
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        }

        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }

    /* Check if option requires an argument */
    if (cp[1] == ':') {
        /* Option requires an argument */
        if (argv[optind][sp + 1] != '\0') {
            /* Argument is in same argv element */
            optarg = &argv[optind++][sp + 1];
        } else if (++optind >= argc) {
            /* Missing required argument */
            if (opterr && *optstring != ':') {
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            }
            sp = 1;
            return ((*optstring == ':') ? ':' : '?');
        } else {
            /* Argument is in next argv element */
            optarg = argv[optind++];
        }
        sp = 1;
    } else {
        /* Option does not require an argument */
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }

    return c;
}

/*
 * getopt_long() - Parse command-line options (long and short)
 *
 * This is a simplified implementation that supports:
 * - Long options (--help, --version, etc.)
 * - Short options (-h, -v, etc.)
 * - Options with arguments (--file foo, -f foo)
 * - Mixed long and short options
 */
int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex) {

    /* Check for end of options */
    if (optind >= argc || argv[optind][0] != '-') {
        return -1;
    }

    /* Handle "--" end of options marker */
    if (strcmp(argv[optind], "--") == 0) {
        optind++;
        return -1;
    }

    /* Check if this is a long option (starts with "--") */
    if (argv[optind][0] == '-' && argv[optind][1] == '-') {
        const char *name = argv[optind] + 2;
        const char *equals = strchr(name, '=');
        size_t name_len = equals ? (size_t)(equals - name) : strlen(name);

        /* Search for matching long option */
        for (int i = 0; longopts[i].name != NULL; i++) {
            if (strncmp(name, longopts[i].name, name_len) == 0 &&
                strlen(longopts[i].name) == name_len) {

                /* Found matching option */
                if (longindex) {
                    *longindex = i;
                }

                optind++;

                /* Handle option argument */
                if (longopts[i].has_arg == required_argument ||
                    longopts[i].has_arg == optional_argument) {

                    if (equals) {
                        /* Argument provided with '=' */
                        optarg = (char *)(equals + 1);
                    } else if (longopts[i].has_arg == required_argument) {
                        /* Argument should be in next argv element */
                        if (optind >= argc) {
                            if (opterr) {
                                fprintf(stderr, "%s: option '--%s' requires an argument\n",
                                       argv[0], longopts[i].name);
                            }
                            return '?';
                        }
                        optarg = argv[optind++];
                    } else {
                        /* Optional argument not provided */
                        optarg = NULL;
                    }
                } else {
                    /* No argument expected */
                    optarg = NULL;
                    if (equals) {
                        if (opterr) {
                            fprintf(stderr, "%s: option '--%s' doesn't allow an argument\n",
                                   argv[0], longopts[i].name);
                        }
                        return '?';
                    }
                }

                /* Handle flag setting or return value */
                if (longopts[i].flag) {
                    *longopts[i].flag = longopts[i].val;
                    return 0;
                } else {
                    return longopts[i].val;
                }
            }
        }

        /* Long option not found */
        if (opterr) {
            fprintf(stderr, "%s: unrecognized option '--%.*s'\n",
                   argv[0], (int)name_len, name);
        }
        optind++;
        return '?';
    }

    /* Not a long option, use regular getopt() for short options */
    return getopt(argc, argv, optstring);
}
