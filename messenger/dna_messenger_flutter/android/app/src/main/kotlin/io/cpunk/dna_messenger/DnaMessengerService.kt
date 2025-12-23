package io.cpunk.dna_messenger

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import java.util.Timer
import java.util.TimerTask

/**
 * DNA Messenger Foreground Service
 *
 * Keeps the DHT connection alive when the app is backgrounded.
 * Polls for offline messages every 60 seconds.
 *
 * Phase 14: Android background execution for reliable DHT-only messaging.
 */
class DnaMessengerService : Service() {
    companion object {
        private const val TAG = "DnaMessengerService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "dna_messenger_service"
        private const val POLL_INTERVAL_MS = 60_000L  // 60 seconds

        @Volatile
        private var isRunning = false

        fun isServiceRunning(): Boolean = isRunning
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var pollTimer: Timer? = null

    override fun onCreate() {
        super.onCreate()
        android.util.Log.i(TAG, "Service created")
        createNotificationChannel()
        isRunning = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: "START"
        android.util.Log.i(TAG, "onStartCommand: action=$action")

        when (action) {
            "START" -> startForegroundService()
            "STOP" -> stopForegroundService()
            "POLL_NOW" -> pollOfflineMessagesNow()
        }

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        android.util.Log.i(TAG, "Service destroyed")
        isRunning = false
        stopPolling()
        releaseWakeLock()
        super.onDestroy()
    }

    private fun startForegroundService() {
        android.util.Log.i(TAG, "Starting foreground service")
        val notification = createNotification("DNA Messenger running")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        acquireWakeLock()
        startPolling()
    }

    private fun stopForegroundService() {
        android.util.Log.i(TAG, "Stopping foreground service")
        stopPolling()
        releaseWakeLock()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DNA Messenger Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps DHT connection alive for message delivery"
                setShowBadge(false)
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DNA Messenger")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info) // TODO: Use app icon
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun updateNotification(text: String) {
        val notification = createNotification(text)
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "DnaMessenger:ServiceWakeLock"
            )
        }
        wakeLock?.let {
            if (!it.isHeld) {
                it.acquire(10 * 60 * 1000L) // 10 minutes max, renewed by timer
                android.util.Log.d(TAG, "WakeLock acquired")
            }
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
                android.util.Log.d(TAG, "WakeLock released")
            }
        }
        wakeLock = null
    }

    private fun startPolling() {
        pollTimer?.cancel()
        pollTimer = Timer("DnaMessengerPollTimer").apply {
            scheduleAtFixedRate(object : TimerTask() {
                override fun run() {
                    pollOfflineMessages()
                    // Renew wake lock periodically
                    acquireWakeLock()
                }
            }, POLL_INTERVAL_MS, POLL_INTERVAL_MS)
        }
        android.util.Log.i(TAG, "Polling started (interval: ${POLL_INTERVAL_MS}ms)")
    }

    private fun stopPolling() {
        pollTimer?.cancel()
        pollTimer = null
        android.util.Log.i(TAG, "Polling stopped")
    }

    private fun pollOfflineMessages() {
        android.util.Log.d(TAG, "Polling for offline messages")
        // Broadcast intent to Flutter to trigger offline message check
        val intent = Intent("io.cpunk.dna_messenger.POLL_MESSAGES")
        sendBroadcast(intent)
    }

    private fun pollOfflineMessagesNow() {
        android.util.Log.i(TAG, "Immediate poll requested")
        pollOfflineMessages()
        updateNotification("Checking for messages...")
        // Reset notification after delay
        android.os.Handler(mainLooper).postDelayed({
            updateNotification("DNA Messenger running")
        }, 2000)
    }
}
