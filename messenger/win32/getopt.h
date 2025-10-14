/*
 * getopt.h - POSIX getopt() and getopt_long() for Windows
 *
 * Minimal getopt/getopt_long implementation for Windows compatibility.
 * Based on public domain implementations.
 */

#ifndef GETOPT_H
#define GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Argument flags */
#define no_argument       0
#define required_argument 1
#define optional_argument 2

/* Option structure for getopt_long */
struct option {
    const char *name;    /* Long option name */
    int has_arg;         /* no_argument, required_argument, or optional_argument */
    int *flag;           /* If not NULL, set *flag to val when option found */
    int val;             /* Value to return (or to set *flag to) */
};

/* Global variables */
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

/* Function declarations */
int getopt(int argc, char * const argv[], const char *optstring);
int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex);

#ifdef __cplusplus
}
#endif

#endif /* GETOPT_H */
