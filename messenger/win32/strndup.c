/*
 * strndup implementation for Windows
 * POSIX function not available in Windows standard library
 */

#include <stdlib.h>
#include <string.h>

char *strndup(const char *s, size_t n) {
    size_t len = strnlen(s, n);
    char *new_str = (char *)malloc(len + 1);
    if (new_str == NULL) {
        return NULL;
    }
    memcpy(new_str, s, len);
    new_str[len] = '\0';
    return new_str;
}
