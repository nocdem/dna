package io.cpunk.dna_connect

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties.BLOCK_MODE_GCM
import android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE
import android.security.keystore.KeyProperties.PURPOSE_DECRYPT
import android.security.keystore.KeyProperties.PURPOSE_ENCRYPT
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * TEE-backed key wrapping using Android Keystore.
 *
 * Generates an AES-256-GCM key in TEE hardware and uses it to wrap/unwrap
 * identity key files. The wrapping key never leaves the secure hardware.
 *
 * Thread-safe: Cipher instances are created per-call, key creation is synchronized.
 *
 * Called via JNI from platform_keystore_android.c.
 */
object DnaKeyStore {
    private const val KEY_ALIAS = "dna_tee_wrap_key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_SIZE = 12

    @Synchronized
    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        ks.getEntry(KEY_ALIAS, null)?.let {
            return (it as KeyStore.SecretKeyEntry).secretKey
        }

        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
            .setBlockModes(BLOCK_MODE_GCM)
            .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .build()

        return KeyGenerator.getInstance("AES", "AndroidKeyStore")
            .apply { init(spec) }
            .generateKey()
    }

    /**
     * Check if TEE-backed keystore is available.
     * Creates the key on first call as a side effect.
     *
     * @return true if keystore is accessible and key can be created, false otherwise
     */
    @JvmStatic
    fun isAvailable(): Boolean {
        return try {
            getOrCreateKey()
            true
        } catch (e: Exception) {
            android.util.Log.w("DnaKeyStore", "TEE keystore unavailable: ${e.message}")
            false
        }
    }

    /**
     * Encrypt data with TEE-backed AES-256-GCM.
     *
     * @param data  Plaintext to encrypt
     * @param aad   Additional authenticated data (DNAT header, 6 bytes)
     * @return      [12-byte IV][ciphertext + 16-byte GCM tag]
     */
    @JvmStatic
    fun encrypt(data: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(aad)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(data)
        return iv + encrypted
    }

    /**
     * Decrypt data with TEE-backed AES-256-GCM.
     *
     * @param data  [12-byte IV][ciphertext + 16-byte GCM tag]
     * @param aad   Additional authenticated data (DNAT header, 6 bytes)
     * @return      Decrypted plaintext
     * @throws javax.crypto.AEADBadTagException if AAD doesn't match or tag invalid
     */
    @JvmStatic
    fun decrypt(data: ByteArray, aad: ByteArray): ByteArray {
        require(data.size > GCM_IV_SIZE) { "Data too short for GCM" }
        val iv = data.sliceArray(0 until GCM_IV_SIZE)
        val ciphertext = data.sliceArray(GCM_IV_SIZE until data.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
