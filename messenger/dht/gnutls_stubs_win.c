/*
 * GnuTLS Stubs for Windows Static Linking
 *
 * The MXE-built OpenDHT library expects DLL import symbols (__imp_*)
 * from gnutls. gnutls_free already exists in libgnutls.a, so we just
 * need to provide the __imp_ pointer that references it.
 */

#ifdef _WIN32

/* Forward declaration of gnutls_free from libgnutls.a */
extern void gnutls_free(void *ptr);

/* Provide the __imp_ pointer that DLL imports expect */
void (*__imp_gnutls_free)(void *) = gnutls_free;

#endif /* _WIN32 */
