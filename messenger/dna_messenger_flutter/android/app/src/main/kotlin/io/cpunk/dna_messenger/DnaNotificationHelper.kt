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
        private const val MESSAGE_CHANNEL_ID = "dna_messages"
        private const val MESSAGE_NOTIFICATION_ID = 2001

        init {
            // Load the native library (may already be loaded by Flutter FFI)
            try {
                System.loadLibrary("dna_lib")
                android.util.Log.i(TAG, "Native library loaded")
            } catch (e: UnsatisfiedLinkError) {
                android.util.Log.e(TAG, "Failed to load native library: ${e.message}")
            }
        }
    }

    // Native method to register this helper
    private external fun nativeSetNotificationHelper(helper: DnaNotificationHelper?)

    init {
        createNotificationChannel()
        registerWithNative()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                MESSAGE_CHANNEL_ID,
                "Messages",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "New message notifications"
                enableVibration(true)
                enableLights(true)
            }
            val notificationManager = context.getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun registerWithNative() {
        try {
            nativeSetNotificationHelper(this)
            android.util.Log.i(TAG, "Registered as notification helper")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to register: ${e.message}")
        }
    }

    /**
     * Called from native code (JNI) when a contact's outbox has new messages.
     * This method is called from a native thread, not the main thread.
     */
    fun onOutboxUpdated(contactFingerprint: String, displayName: String?) {
        android.util.Log.i(TAG, "onOutboxUpdated: fp=${contactFingerprint.take(16)}... name=$displayName")

        // Show notification
        val senderName = displayName ?: "${contactFingerprint.take(8)}..."
        showMessageNotification(senderName, contactFingerprint)
    }

    private fun showMessageNotification(senderName: String, contactFingerprint: String) {
        val pendingIntent = PendingIntent.getActivity(
            context, 0,
            context.packageManager.getLaunchIntentForPackage(context.packageName),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(context, MESSAGE_CHANNEL_ID)
            .setContentTitle("New message")
            .setContentText("From $senderName")
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVibrate(longArrayOf(0, 250, 250, 250))
            .build()

        val notificationManager = context.getSystemService(NotificationManager::class.java)
        // Use fingerprint hash for unique notification ID per contact
        val notificationId = MESSAGE_NOTIFICATION_ID + contactFingerprint.hashCode()
        notificationManager.notify(notificationId, notification)

        android.util.Log.i(TAG, "Notification shown for $senderName")
    }

    fun unregister() {
        try {
            nativeSetNotificationHelper(null)
            android.util.Log.i(TAG, "Unregistered notification helper")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to unregister: ${e.message}")
        }
    }
}
