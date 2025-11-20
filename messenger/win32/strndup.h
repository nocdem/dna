/*
 * strndup declaration for Windows
 * POSIX function not available in Windows standard library
 */

#ifndef STRNDUP_H
#define STRNDUP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char *strndup(const char *s, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* STRNDUP_H */
