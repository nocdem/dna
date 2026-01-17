package io.cpunk.dna_messenger

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
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
    companion object {
        private const val TAG = "MainActivity"
        private const val NOTIFICATION_PERMISSION_REQUEST_CODE = 1002

        /**
         * Singleton notification helper - shared between MainActivity and ForegroundService.
         * Initialized early in MainActivity.onCreate() to catch all DHT events.
         */
        @Volatile
        var notificationHelper: DnaNotificationHelper? = null
            private set

        /**
         * Initialize notification helper if not already initialized.
         * Called early in MainActivity.onCreate() and also from ForegroundService as fallback.
         */
        @Synchronized
        fun initNotificationHelper(context: Context): DnaNotificationHelper? {
            if (notificationHelper == null) {
                try {
                    notificationHelper = DnaNotificationHelper(context.applicationContext)
                    android.util.Log.i(TAG, "Notification helper initialized (singleton)")
                } catch (e: Exception) {
                    android.util.Log.e(TAG, "Failed to initialize notification helper: ${e.message}")
                }
            }
            return notificationHelper
        }

        /**
         * Cleanup notification helper when app is fully destroyed.
         */
        @Synchronized
        fun cleanupNotificationHelper() {
            notificationHelper?.unregister()
            notificationHelper = null
            android.util.Log.i(TAG, "Notification helper cleaned up")
        }
    }

    private var serviceChannel: DnaServiceMethodChannel? = null

    // Broadcast receiver for service poll requests
    private val messageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            android.util.Log.d("MainActivity", "Received poll broadcast from service")
            // The service is requesting a poll - Flutter handles this via MethodChannel callback
            serviceChannel?.notifyNewMessages(0, null) // Trigger refresh
        }
    }

    // Broadcast receiver for network change notifications
    private val networkReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            android.util.Log.i("MainActivity", "Received network change broadcast from service")
            // Notify Flutter to reinitialize DHT connection
            serviceChannel?.notifyNetworkChanged()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize notification helper EARLY - before DHT connects
        // This ensures we catch all DHT events from the very beginning
        initNotificationHelper(this)

        // Copy CA bundle from assets to app data directory for curl SSL
        copyCACertificateBundle()

        // Request notification permission on Android 13+ if notifications are enabled in settings
        // This ensures the foreground service notification is visible
        requestNotificationPermissionIfNeeded()

        // Register broadcast receiver for service messages
        val pollFilter = IntentFilter("io.cpunk.dna_messenger.POLL_MESSAGES")
        val networkFilter = IntentFilter("io.cpunk.dna_messenger.NETWORK_CHANGED")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(messageReceiver, pollFilter, Context.RECEIVER_NOT_EXPORTED)
            registerReceiver(networkReceiver, networkFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(messageReceiver, pollFilter)
            registerReceiver(networkReceiver, networkFilter)
        }
    }

    /**
     * Request notification permission if:
     * - Android 13+ (API 33+)
     * - Permission not already granted
     * - User has notifications enabled in app settings
     *
     * This ensures the foreground service notification is visible when
     * the service starts automatically (e.g., after swipe away or boot).
     */
    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasPermission = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED

            if (hasPermission) {
                android.util.Log.d(TAG, "Notification permission already granted")
                return
            }

            // Check if user has notifications enabled in app settings
            val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
            val notificationsEnabled = prefs.getBoolean("flutter.notifications_enabled", true)

            if (notificationsEnabled) {
                android.util.Log.i(TAG, "Requesting notification permission (notifications enabled in settings)")
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    NOTIFICATION_PERMISSION_REQUEST_CODE
                )
            } else {
                android.util.Log.d(TAG, "Notifications disabled in settings, not requesting permission")
            }
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // Initialize service method channel for Flutter communication
        serviceChannel = DnaServiceMethodChannel(this, flutterEngine)
        android.util.Log.i("MainActivity", "Service MethodChannel configured")
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        // Forward permission results to service channel
        serviceChannel?.onRequestPermissionsResult(requestCode, permissions, grantResults)
    }

    override fun onDestroy() {
        try {
            unregisterReceiver(messageReceiver)
            unregisterReceiver(networkReceiver)
        } catch (e: Exception) {
            // Receivers may not be registered
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
