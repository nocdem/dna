/*
 * dirent.h - POSIX directory functions for Windows
 *
 * Minimal dirent implementation for Windows compatibility.
 * Based on public domain implementations.
 */

#ifndef DIRENT_H
#define DIRENT_H

#ifdef _WIN32

#include <windows.h>
#include <io.h>

/* File types for d_type field */
#define DT_UNKNOWN  0
#define DT_REG      8   /* Regular file */
#define DT_DIR      4   /* Directory */

struct dirent {
    long d_ino;              /* Inode number (always 0 on Windows) */
    unsigned short d_reclen; /* Length of this record */
    unsigned char d_type;    /* Type of file */
    char d_name[260];        /* Filename (null-terminated) */
};

typedef struct {
    struct dirent ent;       /* Current directory entry */
    WIN32_FIND_DATAA data;   /* Windows find data */
    HANDLE handle;           /* Search handle */
    int cached;              /* Flag: entry cached */
} DIR;

#ifdef __cplusplus
extern "C" {
#endif

DIR *opendir(const char *name);
struct dirent *readdir(DIR *dirp);
int closedir(DIR *dirp);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */

#endif /* DIRENT_H */
