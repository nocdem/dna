package io.cpunk.dna_messenger

import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import java.io.File
import java.io.FileOutputStream

class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Copy CA bundle from assets to app data directory for curl SSL
        copyCACertificateBundle()
    }

    /**
     * Copy cacert.pem from assets to app's files directory.
     * This is required for curl to verify SSL certificates on Android.
     */
    private fun copyCACertificateBundle() {
        val destFile = File(filesDir, "cacert.pem")

        // Only copy if not exists or is outdated (check size as simple version check)
        try {
            val assetSize = assets.open("cacert.pem").use { it.available() }
            if (destFile.exists() && destFile.length() == assetSize.toLong()) {
                return // Already up to date
            }
        } catch (e: Exception) {
            // Asset doesn't exist, skip
            return
        }

        try {
            assets.open("cacert.pem").use { input ->
                FileOutputStream(destFile).use { output ->
                    input.copyTo(output)
                }
            }
            android.util.Log.i("DNA", "CA bundle copied to: ${destFile.absolutePath}")
        } catch (e: Exception) {
            android.util.Log.e("DNA", "Failed to copy CA bundle: ${e.message}")
        }
    }
}
