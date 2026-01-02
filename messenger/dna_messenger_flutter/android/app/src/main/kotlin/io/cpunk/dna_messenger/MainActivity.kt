package io.cpunk.dna_messenger

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import java.io.File
import java.io.FileOutputStream

/**
 * DNA Messenger Main Activity
 *
 * Phase 14: Added ForegroundService integration for reliable DHT-only messaging.
 */
class MainActivity : FlutterFragmentActivity() {
    private var serviceChannel: DnaServiceMethodChannel? = null

    // Broadcast receiver for service poll requests
    private val messageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            android.util.Log.d("MainActivity", "Received poll broadcast from service")
            // The service is requesting a poll - Flutter handles this via MethodChannel callback
            serviceChannel?.notifyNewMessages(0, null) // Trigger refresh
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Copy CA bundle from assets to app data directory for curl SSL
        copyCACertificateBundle()

        // Register broadcast receiver for service messages
        val filter = IntentFilter("io.cpunk.dna_messenger.POLL_MESSAGES")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(messageReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(messageReceiver, filter)
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // Initialize service method channel for Flutter communication
        serviceChannel = DnaServiceMethodChannel(this, flutterEngine)
        android.util.Log.i("MainActivity", "Service MethodChannel configured")
    }

    override fun onDestroy() {
        try {
            unregisterReceiver(messageReceiver)
        } catch (e: Exception) {
            // Receiver may not be registered
        }
        super.onDestroy()
    }

    /**
     * Copy cacert.pem from assets to app's dna_messenger data directory.
     * This is required for curl to verify SSL certificates on Android.
     * Must match the path that Flutter uses: filesDir/dna_messenger/cacert.pem
     */
    private fun copyCACertificateBundle() {
        // Create dna_messenger subdirectory to match Flutter's data path
        val dnaDir = File(filesDir, "dna_messenger")
        if (!dnaDir.exists()) {
            dnaDir.mkdirs()
        }

        val destFile = File(dnaDir, "cacert.pem")

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
