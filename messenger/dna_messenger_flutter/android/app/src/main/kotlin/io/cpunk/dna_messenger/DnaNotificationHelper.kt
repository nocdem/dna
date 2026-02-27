package io.cpunk.dna_messenger

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat

/**
 * DNA Notification Helper
 *
 * Receives callbacks from the native library when a contact's outbox has new messages.
 * This allows showing native Android notifications even when Flutter is backgrounded.
 *
 * The native library calls onOutboxUpdated() via JNI when DNA_EVENT_OUTBOX_UPDATED fires.
 */
class DnaNotificationHelper(private val context: Context) {
    companion object {
        private const val TAG = "DnaNotificationHelper"
        // v2: Fresh channel ID to guarantee IMPORTANCE_HIGH (Android caches channel settings)
        private const val MESSAGE_CHANNEL_ID = "dna_messages_v2"
        private const val OLD_CHANNEL_ID = "dna_messages"
        private const val MESSAGE_NOTIFICATION_ID = 2001

        // Flutter SharedPreferences file and key
        private const val FLUTTER_PREFS_FILE = "FlutterSharedPreferences"
        private const val NOTIFICATIONS_ENABLED_KEY = "flutter.notifications_enabled"

        private var nativeLogAvailable = false

        init {
            // Load the native library (may already be loaded by Flutter FFI)
            try {
                System.loadLibrary("dna_lib")
                nativeLogAvailable = true
                android.util.Log.i(TAG, "Native library loaded")
            } catch (e: UnsatisfiedLinkError) {
                android.util.Log.e(TAG, "Failed to load native library: ${e.message}")
            }
        }
    }

    // Track which contacts we've already notified (prevent repeated alerts)
    private val notifiedContacts = mutableSetOf<String>()

    /** Log to both logcat and dna.log via JNI */
    private fun dnaLog(msg: String) {
        android.util.Log.i(TAG, msg)
        try {
            if (nativeLogAvailable) nativeLogToDna(msg)
        } catch (_: Exception) {}
    }

    /**
     * Check if notifications are enabled in user settings
     */
    private fun areNotificationsEnabled(): Boolean {
        val prefs = context.getSharedPreferences(FLUTTER_PREFS_FILE, Context.MODE_PRIVATE)
        // Default to true if not set
        return prefs.getBoolean(NOTIFICATIONS_ENABLED_KEY, true)
    }

    // Native methods
    private external fun nativeSetNotificationHelper(helper: DnaNotificationHelper?)
    private external fun nativeLogToDna(message: String)

    init {
        createNotificationChannel()
        registerWithNative()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = context.getSystemService(NotificationManager::class.java)

            // Delete old channel (importance was cached at DEFAULT)
            notificationManager.deleteNotificationChannel(OLD_CHANNEL_ID)

            // Create v2 channel with guaranteed IMPORTANCE_HIGH
            val messageChannel = NotificationChannel(
                MESSAGE_CHANNEL_ID,
                "Messages",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "New message notifications"
                enableVibration(true)
                enableLights(true)
            }
            notificationManager.createNotificationChannel(messageChannel)
        }
    }

    private fun registerWithNative() {
        try {
            nativeSetNotificationHelper(this)
            dnaLog("Registered as notification helper")
        } catch (e: Exception) {
            dnaLog("ERROR: Failed to register: ${e.message}")
        }
    }

    /**
     * Called from native code (JNI) when a contact's outbox has new messages.
     * This method is called from a native thread, not the main thread.
     */
    fun onOutboxUpdated(contactFingerprint: String, displayName: String?) {
        // Deduplicate: only alert once per contact until cleared
        synchronized(notifiedContacts) {
            if (notifiedContacts.contains(contactFingerprint)) {
                dnaLog("onOutboxUpdated: fp=${contactFingerprint.take(16)}... SKIP (already notified)")
                return
            }
            notifiedContacts.add(contactFingerprint)
        }

        dnaLog("onOutboxUpdated: fp=${contactFingerprint.take(16)}... name=$displayName")

        // Check if user has notifications enabled
        if (!areNotificationsEnabled()) {
            dnaLog("Notifications disabled by user, skipping")
            return
        }

        // Check POST_NOTIFICATIONS permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasPermission = context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
            if (!hasPermission) {
                dnaLog("ERROR: POST_NOTIFICATIONS permission NOT granted")
                return
            }
        }

        // Show notification
        val senderName = displayName ?: "${contactFingerprint.take(8)}..."
        try {
            showMessageNotification(senderName, contactFingerprint)
        } catch (e: Exception) {
            dnaLog("ERROR: showMessageNotification failed: ${e.message}")
        }
    }

    private fun showMessageNotification(senderName: String, contactFingerprint: String) {
        val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
        if (launchIntent == null) {
            dnaLog("ERROR: getLaunchIntentForPackage returned null")
            return
        }

        val pendingIntent = PendingIntent.getActivity(
            context, 0, launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(context, MESSAGE_CHANNEL_ID)
            .setContentTitle(senderName)
            .setContentText("New message received")
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVibrate(longArrayOf(0, 250, 250, 250))
            .setOnlyAlertOnce(true)  // Don't re-alert if notification already showing
            .setLocalOnly(false)
            .build()

        val notificationManager = context.getSystemService(NotificationManager::class.java)
        val notificationId = MESSAGE_NOTIFICATION_ID + contactFingerprint.hashCode()
        notificationManager.notify(notificationId, notification)
        dnaLog("Notification posted for $senderName (id=$notificationId)")
    }

    /**
     * Clear notification state when Flutter becomes active.
     * Called from service when user opens the app.
     */
    fun clearNotifications() {
        synchronized(notifiedContacts) {
            notifiedContacts.clear()
        }
        // Cancel all message notifications
        val notificationManager = context.getSystemService(NotificationManager::class.java)
        notificationManager.cancelAll()
        dnaLog("Notifications cleared (Flutter active)")
    }

    /**
     * Called from native code (JNI) when a contact request is received.
     * This method is called from a native thread, not the main thread.
     */
    fun onContactRequestReceived(userFingerprint: String, displayName: String?) {
        dnaLog("onContactRequestReceived: fp=${userFingerprint.take(16)}... name=$displayName")

        if (!areNotificationsEnabled()) {
            dnaLog("Notifications disabled by user, skipping")
            return
        }

        val senderName = displayName ?: "${userFingerprint.take(8)}..."
        try {
            showContactRequestNotification(senderName, userFingerprint)
        } catch (e: Exception) {
            dnaLog("ERROR: showContactRequestNotification failed: ${e.message}")
        }
    }

    private fun showContactRequestNotification(senderName: String, userFingerprint: String) {
        val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
        if (launchIntent == null) {
            dnaLog("ERROR: getLaunchIntentForPackage returned null for contact request")
            return
        }

        val pendingIntent = PendingIntent.getActivity(
            context, 0, launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(context, MESSAGE_CHANNEL_ID)
            .setContentTitle("Contact Request")
            .setContentText("$senderName wants to add you as a contact")
            .setSmallIcon(android.R.drawable.ic_menu_add)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_SOCIAL)
            .setVibrate(longArrayOf(0, 250, 250, 250))
            .setOnlyAlertOnce(true)
            .setLocalOnly(false)
            .build()

        val notificationManager = context.getSystemService(NotificationManager::class.java)
        val notificationId = MESSAGE_NOTIFICATION_ID + 10000 + userFingerprint.hashCode()
        notificationManager.notify(notificationId, notification)

        dnaLog("Contact request notification posted for $senderName (id=$notificationId)")
    }

    fun unregister() {
        try {
            nativeSetNotificationHelper(null)
            dnaLog("Unregistered notification helper")
        } catch (e: Exception) {
            dnaLog("ERROR: Failed to unregister: ${e.message}")
        }
    }
}
