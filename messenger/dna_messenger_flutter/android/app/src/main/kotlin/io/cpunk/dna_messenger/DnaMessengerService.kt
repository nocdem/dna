package io.cpunk.dna_messenger

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
 * Monitors network changes and notifies Flutter to reinitialize DHT.
 *
 * Phase 14: Android background execution for reliable DHT-only messaging.
 */
class DnaMessengerService : Service() {
    companion object {
        private const val TAG = "DnaMessengerService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "dna_messenger_service"
        private const val POLL_INTERVAL_MS = 60_000L  // 60 seconds
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 2000L  // 2 seconds debounce

        @Volatile
        private var isRunning = false

        fun isServiceRunning(): Boolean = isRunning
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var pollTimer: Timer? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkChangeTime: Long = 0
    private var currentNetworkId: String? = null
    private var hadPreviousNetwork: Boolean = false  // Track if we had a network before disconnect
    private var notificationHelper: DnaNotificationHelper? = null

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

    override fun onTaskRemoved(rootIntent: Intent?) {
        android.util.Log.i(TAG, "Task removed - scheduling service restart")

        // Only restart if notifications are enabled
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        val notificationsEnabled = prefs.getBoolean("flutter.notifications_enabled", true)

        if (notificationsEnabled) {
            // Schedule restart via AlarmManager for immediate restart
            val restartIntent = Intent(this, DnaMessengerService::class.java).apply {
                action = "START"
            }
            val pendingIntent = PendingIntent.getService(
                this, 1, restartIntent,
                PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
            )

            val alarmManager = getSystemService(Context.ALARM_SERVICE) as AlarmManager
            alarmManager.set(
                AlarmManager.RTC_WAKEUP,
                System.currentTimeMillis() + 1000, // 1 second delay
                pendingIntent
            )
            android.util.Log.i(TAG, "Service restart scheduled")
        }

        super.onTaskRemoved(rootIntent)
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
        registerNetworkCallback()

        // Initialize native notification helper for background message notifications
        try {
            notificationHelper = DnaNotificationHelper(this)
            android.util.Log.i(TAG, "Notification helper initialized")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to initialize notification helper: ${e.message}")
        }
    }

    private fun stopForegroundService() {
        android.util.Log.i(TAG, "Stopping foreground service")

        // Unregister notification helper
        notificationHelper?.unregister()
        notificationHelper = null

        unregisterNetworkCallback()
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

    // ========== NETWORK MONITORING ==========

    private fun registerNetworkCallback() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            android.util.Log.w(TAG, "Network monitoring not available on API < 21")
            return
        }

        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val networkId = network.toString()
                android.util.Log.i(TAG, "Network available: $networkId (previous: $currentNetworkId, hadPrevious: $hadPreviousNetwork)")

                // Trigger reconnect if:
                // 1. We're switching directly between networks (currentNetworkId != null && different)
                // 2. We lost previous network and got a new one (hadPreviousNetwork && currentNetworkId == null)
                val shouldReconnect = when {
                    currentNetworkId != null && currentNetworkId != networkId -> true  // Direct switch
                    hadPreviousNetwork && currentNetworkId == null -> true  // Reconnect after disconnect
                    else -> false  // Initial connect, no need to reinit
                }

                if (shouldReconnect) {
                    handleNetworkChange(networkId)
                }

                currentNetworkId = networkId
                hadPreviousNetwork = true  // We now have a network
            }

            override fun onLost(network: Network) {
                val networkId = network.toString()
                android.util.Log.i(TAG, "Network lost: $networkId")

                // Clear current network if it's the one that was lost
                if (currentNetworkId == networkId) {
                    currentNetworkId = null
                    // Don't clear hadPreviousNetwork - we want to trigger reconnect when new network appears
                }
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                // Log network type changes (WiFi <-> Cellular)
                val hasWifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                val hasCellular = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                android.util.Log.d(TAG, "Network capabilities changed: wifi=$hasWifi, cellular=$hasCellular")
            }
        }

        try {
            connectivityManager?.registerNetworkCallback(request, networkCallback!!)
            android.util.Log.i(TAG, "Network callback registered")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to register network callback: ${e.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let { callback ->
            try {
                connectivityManager?.unregisterNetworkCallback(callback)
                android.util.Log.i(TAG, "Network callback unregistered")
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Failed to unregister network callback: ${e.message}")
            }
        }
        networkCallback = null
        connectivityManager = null
        currentNetworkId = null
        hadPreviousNetwork = false
    }

    private fun handleNetworkChange(newNetworkId: String) {
        val now = System.currentTimeMillis()

        // Debounce rapid network changes (e.g., WiFi disconnect/cellular connect)
        if (now - lastNetworkChangeTime < NETWORK_CHANGE_DEBOUNCE_MS) {
            android.util.Log.d(TAG, "Network change debounced (too soon after previous)")
            return
        }
        lastNetworkChangeTime = now

        android.util.Log.i(TAG, "Network changed to $newNetworkId - notifying Flutter to reinit DHT")
        updateNotification("Reconnecting...")

        // Broadcast intent to Flutter to trigger DHT reconnect
        val intent = Intent("io.cpunk.dna_messenger.NETWORK_CHANGED")
        sendBroadcast(intent)

        // Reset notification after delay
        android.os.Handler(mainLooper).postDelayed({
            updateNotification("DNA Messenger running")
        }, 3000)
    }
}
