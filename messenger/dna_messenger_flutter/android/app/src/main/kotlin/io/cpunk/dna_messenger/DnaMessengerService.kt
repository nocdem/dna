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

/**
 * DNA Messenger Foreground Service
 *
 * Keeps the DHT connection alive when the app is backgrounded.
 * DHT listeners provide real-time push notifications for messages.
 * Monitors network changes and reinitializes DHT when network switches.
 *
 * Phase 14: Android background execution for reliable DHT-only messaging.
 * Note: Polling removed in favor of DHT listeners for better battery life.
 *
 * v0.5.5+: Lightweight background mode available via DNAEngine:
 * - loadIdentityBackground(): Load identity with minimal resources
 * - upgradeToForeground(): Complete initialization when app opens
 * See io.cpunk.dna.DNAEngine for integration.
 */
class DnaMessengerService : Service() {
    companion object {
        private const val TAG = "DnaMessengerService"
        private const val NOTIFICATION_ID = 1001

        // Ensure native library is loaded before any JNI calls
        private var libraryLoaded = false

        init {
            try {
                System.loadLibrary("dna_lib")
                libraryLoaded = true
                android.util.Log.i(TAG, "Native library loaded in service companion")
            } catch (e: UnsatisfiedLinkError) {
                android.util.Log.e(TAG, "Failed to load native library: ${e.message}")
            }
        }
        private const val CHANNEL_ID = "dna_messenger_service"
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 2000L  // 2 seconds debounce
        private const val WAKELOCK_TIMEOUT_MS = 30 * 60 * 1000L  // 30 minutes
        private const val LISTEN_RENEWAL_INTERVAL_MS = 5 * 60 * 60 * 1000L  // 5 hours (before 6h expiry)
        private const val HEALTH_CHECK_INTERVAL_MS = 15 * 60 * 1000L  // 15 minutes
        private const val MAX_RECONNECT_RETRIES = 5
        private val RECONNECT_BACKOFF_MS = longArrayOf(1000, 2000, 5000, 10000, 30000)  // Exponential backoff

        @Volatile
        private var isRunning = false

        fun isServiceRunning(): Boolean = isRunning

        /**
         * Direct DHT reinit via JNI - doesn't need Flutter/engine.
         * Called when network changes while app is backgrounded.
         * Returns: 0 success, -1 DHT not initialized, -2 reinit failed
         */
        @JvmStatic
        external fun nativeReinitDht(): Int

        /**
         * Check if DHT is connected and listeners are active.
         * Returns: true if DHT is healthy, false otherwise
         */
        @JvmStatic
        external fun nativeIsDhtHealthy(): Boolean

        /**
         * Initialize engine if not already done.
         * Called when service starts fresh (after process killed).
         * Returns: true if engine is ready (created or already existed)
         */
        @JvmStatic
        external fun nativeEnsureEngine(dataDir: String): Boolean

        /**
         * Check if identity is already loaded.
         * Returns: true if identity loaded, false if need to load
         */
        @JvmStatic
        external fun nativeIsIdentityLoaded(): Boolean

        /**
         * Load identity in background mode (DHT + listeners only).
         * Called when service starts fresh but Flutter isn't running.
         * Note: This is a blocking call for simplicity in service context.
         * Returns: 0 on success, negative on error
         */
        @JvmStatic
        external fun nativeLoadIdentityBackgroundSync(fingerprint: String): Int

        /**
         * Get current init mode.
         * Returns: 0 = FULL, 1 = BACKGROUND
         */
        @JvmStatic
        external fun nativeGetInitMode(): Int
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkChangeTime: Long = 0
    private var currentNetworkId: String? = null
    private var hadPreviousNetwork: Boolean = false  // Track if we had a network before disconnect
    private var reconnectRetryCount: Int = 0
    private var listenRenewalHandler: android.os.Handler? = null
    private var healthCheckHandler: android.os.Handler? = null
    private var wakeLockRenewalHandler: android.os.Handler? = null

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
        }

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        android.util.Log.i(TAG, "Service destroyed")
        isRunning = false
        releaseWakeLock()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        android.util.Log.i(TAG, "Task removed - scheduling service restart")

        // Only restart if notifications are enabled
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        val notificationsEnabled = prefs.getBoolean("flutter.notifications_enabled", true)
        android.util.Log.i(TAG, "Notifications enabled in prefs: $notificationsEnabled")

        if (notificationsEnabled) {
            // Re-post the foreground notification immediately to prevent it from being dismissed
            // This is needed because some Android versions briefly hide the notification on task removal
            try {
                val notification = createNotification("Decentralized mode active — background service running to receive messages")
                val notificationManager = getSystemService(NotificationManager::class.java)
                notificationManager.notify(NOTIFICATION_ID, notification)
                android.util.Log.i(TAG, "Re-posted foreground notification")
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Failed to re-post notification: ${e.message}")
            }

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
            android.util.Log.i(TAG, "Service restart scheduled via AlarmManager")
        }

        super.onTaskRemoved(rootIntent)
    }

    private fun startForegroundService() {
        android.util.Log.i(TAG, "Starting foreground service")

        // Ensure notification channel exists before starting foreground
        createNotificationChannel()

        // Check notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasPermission = checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
            android.util.Log.i(TAG, "Notification permission granted: $hasPermission")
            if (!hasPermission) {
                android.util.Log.w(TAG, "POST_NOTIFICATIONS permission not granted - foreground notification may not show")
            }
        }

        val notification = createNotification("Decentralized mode active — background service running to receive messages")
        android.util.Log.i(TAG, "Created notification with ID=$NOTIFICATION_ID, channel=$CHANNEL_ID")

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            android.util.Log.i(TAG, "startForeground() called successfully")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "startForeground() failed: ${e.message}")
        }

        acquireWakeLock()
        registerNetworkCallback()
        startListenRenewalTimer()
        startHealthCheckTimer()

        // Use singleton notification helper from MainActivity
        // If not initialized yet (service started without MainActivity), init it now
        if (MainActivity.notificationHelper == null) {
            MainActivity.initNotificationHelper(this)
        }
        android.util.Log.i(TAG, "Using singleton notification helper: ${MainActivity.notificationHelper != null}")

        // v0.5.5+: Check if identity needs to be loaded in background mode
        // This handles the case where process was killed but service restarts
        ensureIdentityLoaded()
    }

    /**
     * Ensure identity is loaded for DHT listeners (v0.5.5+)
     *
     * When the process is killed but service restarts (START_STICKY),
     * we need to reload identity in BACKGROUND mode for notifications.
     */
    private fun ensureIdentityLoaded() {
        if (!libraryLoaded) {
            android.util.Log.e(TAG, "Native library not loaded - cannot ensure identity")
            return
        }

        try {
            // Check if identity already loaded (Flutter might have done it)
            if (nativeIsIdentityLoaded()) {
                val mode = nativeGetInitMode()
                android.util.Log.i(TAG, "Identity already loaded (mode=$mode)")
                return
            }

            // Get fingerprint from SharedPreferences (set by Flutter)
            val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
            val fingerprint = prefs.getString("flutter.identity_fingerprint", null)
            if (fingerprint.isNullOrEmpty()) {
                android.util.Log.i(TAG, "No stored fingerprint - waiting for Flutter to create identity")
                return
            }

            // Ensure engine is initialized
            val dataDir = filesDir.absolutePath + "/dna_messenger"
            if (!nativeEnsureEngine(dataDir)) {
                android.util.Log.e(TAG, "Failed to ensure engine")
                return
            }

            // Load identity in BACKGROUND mode (DHT + listeners only)
            android.util.Log.i(TAG, "Loading identity in BACKGROUND mode: ${fingerprint.take(16)}...")
            val result = nativeLoadIdentityBackgroundSync(fingerprint)
            if (result == 0) {
                android.util.Log.i(TAG, "Identity loaded in BACKGROUND mode - notifications active")
            } else {
                android.util.Log.e(TAG, "Failed to load identity: $result")
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "ensureIdentityLoaded error: ${e.message}")
        }
    }

    private fun stopForegroundService() {
        android.util.Log.i(TAG, "Stopping foreground service")

        // Note: Don't unregister notification helper here - it's managed by MainActivity
        // and may be needed for future service restarts

        stopListenRenewalTimer()
        stopHealthCheckTimer()
        unregisterNetworkCallback()
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
            val notificationManager = getSystemService(NotificationManager::class.java)

            // Check if channel already exists
            val existingChannel = notificationManager.getNotificationChannel(CHANNEL_ID)
            if (existingChannel != null) {
                android.util.Log.d(TAG, "Notification channel exists, importance=${existingChannel.importance}")
                // Check if user disabled the channel
                if (existingChannel.importance == NotificationManager.IMPORTANCE_NONE) {
                    android.util.Log.w(TAG, "Notification channel is disabled by user!")
                }
                return
            }

            val channel = NotificationChannel(
                CHANNEL_ID,
                "DNA Messenger Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps DHT connection alive for message delivery"
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
            android.util.Log.i(TAG, "Created notification channel: $CHANNEL_ID")
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
                it.acquire(WAKELOCK_TIMEOUT_MS)
                android.util.Log.d(TAG, "WakeLock acquired (${WAKELOCK_TIMEOUT_MS / 60000} min timeout)")
            }
        }
        // Schedule renewal before expiry
        startWakeLockRenewal()
    }

    private fun startWakeLockRenewal() {
        wakeLockRenewalHandler?.removeCallbacksAndMessages(null)
        wakeLockRenewalHandler = android.os.Handler(mainLooper)
        val renewalInterval = WAKELOCK_TIMEOUT_MS - 60000  // Renew 1 minute before expiry
        wakeLockRenewalHandler?.postDelayed(object : Runnable {
            override fun run() {
                if (isRunning && wakeLock != null) {
                    wakeLock?.let {
                        if (it.isHeld) {
                            it.release()
                        }
                        it.acquire(WAKELOCK_TIMEOUT_MS)
                        android.util.Log.d(TAG, "WakeLock renewed")
                    }
                    wakeLockRenewalHandler?.postDelayed(this, renewalInterval)
                }
            }
        }, renewalInterval)
    }

    private fun releaseWakeLock() {
        wakeLockRenewalHandler?.removeCallbacksAndMessages(null)
        wakeLockRenewalHandler = null
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
                android.util.Log.d(TAG, "WakeLock released")
            }
        }
        wakeLock = null
    }

    // ========== LISTEN RENEWAL (prevent 6-hour OpenDHT expiry) ==========

    private fun startListenRenewalTimer() {
        listenRenewalHandler?.removeCallbacksAndMessages(null)
        listenRenewalHandler = android.os.Handler(mainLooper)
        listenRenewalHandler?.postDelayed(object : Runnable {
            override fun run() {
                if (isRunning) {
                    android.util.Log.i(TAG, "Listen renewal timer fired - reinitializing DHT to refresh subscriptions")
                    performDhtReinit()
                    listenRenewalHandler?.postDelayed(this, LISTEN_RENEWAL_INTERVAL_MS)
                }
            }
        }, LISTEN_RENEWAL_INTERVAL_MS)
        android.util.Log.i(TAG, "Listen renewal timer started (${LISTEN_RENEWAL_INTERVAL_MS / 3600000}h interval)")
    }

    private fun stopListenRenewalTimer() {
        listenRenewalHandler?.removeCallbacksAndMessages(null)
        listenRenewalHandler = null
        android.util.Log.i(TAG, "Listen renewal timer stopped")
    }

    // ========== DHT HEALTH CHECK ==========

    private fun startHealthCheckTimer() {
        healthCheckHandler?.removeCallbacksAndMessages(null)
        healthCheckHandler = android.os.Handler(mainLooper)
        healthCheckHandler?.postDelayed(object : Runnable {
            override fun run() {
                if (isRunning) {
                    performHealthCheck()
                    healthCheckHandler?.postDelayed(this, HEALTH_CHECK_INTERVAL_MS)
                }
            }
        }, HEALTH_CHECK_INTERVAL_MS)
        android.util.Log.i(TAG, "Health check timer started (${HEALTH_CHECK_INTERVAL_MS / 60000}min interval)")
    }

    private fun stopHealthCheckTimer() {
        healthCheckHandler?.removeCallbacksAndMessages(null)
        healthCheckHandler = null
        android.util.Log.i(TAG, "Health check timer stopped")
    }

    private fun performHealthCheck() {
        if (!libraryLoaded) return

        try {
            val isHealthy = nativeIsDhtHealthy()
            android.util.Log.d(TAG, "DHT health check: healthy=$isHealthy")
            if (!isHealthy && isNetworkValidated()) {
                android.util.Log.w(TAG, "DHT unhealthy but network available - triggering reinit")
                performDhtReinit()
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Health check error: ${e.message}")
        }
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

    private var lastReconnectNetworkId: String? = null

    private fun handleNetworkChange(newNetworkId: String) {
        val now = System.currentTimeMillis()

        // Smart debounce: only debounce rapid reconnects to the SAME network.
        // If switching to a DIFFERENT network, always reconnect immediately.
        val isSameNetwork = lastReconnectNetworkId == newNetworkId
        if (isSameNetwork && now - lastNetworkChangeTime < NETWORK_CHANGE_DEBOUNCE_MS) {
            android.util.Log.d(TAG, "Network change debounced (same network $newNetworkId, too soon)")
            return
        }

        lastNetworkChangeTime = now
        lastReconnectNetworkId = newNetworkId
        reconnectRetryCount = 0  // Reset retry count on new network change

        android.util.Log.i(TAG, "Network changed to $newNetworkId (same=$isSameNetwork) - checking connectivity...")
        updateNotification("Reconnecting...")

        attemptReconnectWithBackoff()
    }

    private fun attemptReconnectWithBackoff() {
        if (!isNetworkValidated()) {
            if (reconnectRetryCount < MAX_RECONNECT_RETRIES) {
                val delay = RECONNECT_BACKOFF_MS[reconnectRetryCount.coerceAtMost(RECONNECT_BACKOFF_MS.size - 1)]
                reconnectRetryCount++
                android.util.Log.w(TAG, "Network not validated, retry $reconnectRetryCount/$MAX_RECONNECT_RETRIES in ${delay}ms")
                android.os.Handler(mainLooper).postDelayed({
                    if (isRunning) {
                        attemptReconnectWithBackoff()
                    }
                }, delay)
            } else {
                android.util.Log.e(TAG, "Max reconnect retries reached, giving up")
                updateNotification("Decentralized mode active — background service running to receive messages")
                reconnectRetryCount = 0
            }
            return
        }

        performDhtReinit()
    }

    /**
     * Check if current network has validated internet connectivity
     */
    private fun isNetworkValidated(): Boolean {
        val cm = connectivityManager ?: return false
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false

        // Check for actual internet connectivity (not just connection)
        val hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        val isValidated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)

        android.util.Log.d(TAG, "Network check: hasInternet=$hasInternet, isValidated=$isValidated")
        return hasInternet && isValidated
    }

    /**
     * Perform actual DHT reinitialization
     */
    private fun performDhtReinit() {
        if (!libraryLoaded) {
            android.util.Log.e(TAG, "Native library not loaded - cannot reinit DHT")
            return
        }

        android.util.Log.i(TAG, "Network validated - reinitializing DHT")

        // Reinit DHT directly via JNI (works even when Flutter isn't running)
        try {
            val result = nativeReinitDht()
            when (result) {
                0 -> {
                    android.util.Log.i(TAG, "DHT reinit successful")
                    // Verify listeners restarted after a delay (listener setup is async)
                    scheduleListenerVerification()
                }
                -1 -> android.util.Log.d(TAG, "DHT not initialized yet, skipping reinit")
                else -> android.util.Log.e(TAG, "DHT reinit failed: $result")
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "DHT reinit error: ${e.message}")
        }

        // Also broadcast to Flutter (if running) to refresh listeners
        val intent = Intent("io.cpunk.dna_messenger.NETWORK_CHANGED")
        sendBroadcast(intent)

        // Reset notification after delay
        android.os.Handler(mainLooper).postDelayed({
            updateNotification("Decentralized mode active — background service running to receive messages")
        }, 3000)
    }

    /**
     * Verify listeners restarted after DHT reinit.
     * Listener setup is async (runs on background thread), so we check after a delay.
     * If listeners didn't start, trigger another reinit.
     */
    private var listenerVerificationRetries = 0
    private val MAX_LISTENER_VERIFICATION_RETRIES = 3
    private val LISTENER_VERIFICATION_DELAY_MS = 10000L  // 10 seconds

    private fun scheduleListenerVerification() {
        android.os.Handler(mainLooper).postDelayed({
            if (!isRunning) return@postDelayed

            val isHealthy = try {
                if (libraryLoaded) nativeIsDhtHealthy() else false
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Listener verification error: ${e.message}")
                false
            }

            if (isHealthy) {
                android.util.Log.i(TAG, "Listener verification: DHT healthy, listeners active")
                listenerVerificationRetries = 0
            } else {
                listenerVerificationRetries++
                if (listenerVerificationRetries < MAX_LISTENER_VERIFICATION_RETRIES) {
                    android.util.Log.w(TAG, "Listener verification: unhealthy, retry $listenerVerificationRetries/$MAX_LISTENER_VERIFICATION_RETRIES")
                    performDhtReinit()
                } else {
                    android.util.Log.e(TAG, "Listener verification: failed after $MAX_LISTENER_VERIFICATION_RETRIES retries")
                    listenerVerificationRetries = 0
                }
            }
        }, LISTENER_VERIFICATION_DELAY_MS)
    }
}
