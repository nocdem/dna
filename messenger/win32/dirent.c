/*
 * dirent.c - POSIX directory functions for Windows
 *
 * Minimal dirent implementation using Windows FindFirstFile/FindNextFile.
 */

#ifdef _WIN32

#include "dirent.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

DIR *opendir(const char *name) {
    DIR *dirp;
    char *pattern;
    size_t name_len;

    if (!name || !*name) {
        errno = EINVAL;
        return NULL;
    }

    /* Allocate DIR structure */
    dirp = (DIR *)malloc(sizeof(DIR));
    if (!dirp) {
        errno = ENOMEM;
        return NULL;
    }

    /* Build search pattern: "path\*" */
    name_len = strlen(name);
    pattern = (char *)malloc(name_len + 3); /* +3 for "\*" + null */
    if (!pattern) {
        free(dirp);
        errno = ENOMEM;
        return NULL;
    }

    strcpy(pattern, name);
    /* Add backslash if not present */
    if (name_len > 0 && name[name_len - 1] != '\\' && name[name_len - 1] != '/') {
        strcat(pattern, "\\");
    }
    strcat(pattern, "*");

    /* Start search */
    dirp->handle = FindFirstFileA(pattern, &dirp->data);
    free(pattern);

    if (dirp->handle == INVALID_HANDLE_VALUE) {
        free(dirp);
        errno = ENOENT;
        return NULL;
    }

    dirp->cached = 1; /* First entry is cached */
    return dirp;
}

struct dirent *readdir(DIR *dirp) {
    if (!dirp) {
        errno = EBADF;
        return NULL;
    }

    /* Use cached entry if available */
    if (dirp->cached) {
        dirp->cached = 0;
    } else {
        /* Get next entry */
        if (!FindNextFileA(dirp->handle, &dirp->data)) {
            return NULL;
        }
    }

    /* Fill dirent structure */
    dirp->ent.d_ino = 0;
    dirp->ent.d_reclen = sizeof(struct dirent);
    strncpy(dirp->ent.d_name, dirp->data.cFileName, sizeof(dirp->ent.d_name) - 1);
    dirp->ent.d_name[sizeof(dirp->ent.d_name) - 1] = '\0';

    /* Set file type */
    if (dirp->data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        dirp->ent.d_type = DT_DIR;
    } else {
        dirp->ent.d_type = DT_REG;
    }

    return &dirp->ent;
}

int closedir(DIR *dirp) {
    if (!dirp) {
        errno = EBADF;
        return -1;
    }

    if (dirp->handle != INVALID_HANDLE_VALUE) {
        FindClose(dirp->handle);
    }

    free(dirp);
    return 0;
}

#endif /* _WIN32 */
