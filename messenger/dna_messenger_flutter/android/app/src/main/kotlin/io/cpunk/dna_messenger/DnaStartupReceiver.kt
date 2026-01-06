package io.cpunk.dna_messenger

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

/**
 * BroadcastReceiver that starts the DNA Messenger service on:
 * - Device boot (BOOT_COMPLETED)
 * - App update (MY_PACKAGE_REPLACED)
 *
 * This ensures notifications work immediately after updates without
 * requiring the user to manually launch the app.
 */
class DnaStartupReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "DnaStartupReceiver"

        // SharedPreferences keys (must match Flutter)
        private const val FLUTTER_PREFS_FILE = "FlutterSharedPreferences"
        private const val NOTIFICATIONS_ENABLED_KEY = "flutter.notifications_enabled"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        android.util.Log.i(TAG, "Received broadcast: $action")

        when (action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                // Only start service if user has notifications enabled
                // If notifications are disabled, they don't need background service
                if (areNotificationsEnabled(context)) {
                    android.util.Log.i(TAG, "Starting service after $action")
                    startService(context)
                } else {
                    android.util.Log.i(TAG, "Notifications disabled, skipping service auto-start")
                }
            }
        }
    }

    private fun areNotificationsEnabled(context: Context): Boolean {
        val prefs = context.getSharedPreferences(FLUTTER_PREFS_FILE, Context.MODE_PRIVATE)
        // Default to true - most users want notifications
        return prefs.getBoolean(NOTIFICATIONS_ENABLED_KEY, true)
    }

    private fun startService(context: Context) {
        try {
            val serviceIntent = Intent(context, DnaMessengerService::class.java).apply {
                action = "START"
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
            android.util.Log.i(TAG, "Service start requested")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to start service: ${e.message}")
        }
    }
}
