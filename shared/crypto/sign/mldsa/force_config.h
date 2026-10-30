#ifndef QGP_MLDSA_FORCE_CONFIG_H
#define QGP_MLDSA_FORCE_CONFIG_H
/* Suppress the existing mode-5 config without changing that file. */
#define CONFIG_H
#define DILITHIUM_RANDOMIZED_SIGNING
#if QGP_MLDSA_MODE == 2
#define DILITHIUM_MODE 2
#define CRYPTO_ALGNAME "Dilithium2"
#define DILITHIUM_NAMESPACETOP qgp_mldsa44_private
#define DILITHIUM_NAMESPACE(s) qgp_mldsa44_private_##s
#elif QGP_MLDSA_MODE == 3
#define DILITHIUM_MODE 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACETOP qgp_mldsa65_private
#define DILITHIUM_NAMESPACE(s) qgp_mldsa65_private_##s
#else
#error Unsupported private ML-DSA mode
#endif
#define qgp_randombytes qgp_mldsa_private_randombytes_unavailable
#endif
