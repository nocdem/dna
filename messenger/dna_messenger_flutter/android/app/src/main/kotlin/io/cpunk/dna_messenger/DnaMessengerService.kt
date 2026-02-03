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
 * DNA Messenger Foreground Service (v0.100.20+)
 *
 * Battery-optimized background service for message notifications.
 * Uses periodic polling (every 5 minutes) instead of continuous DHT listeners.
 *
 * Architecture:
 * - Sleep most of the time (no wakelock)
 * - Wake every 5 min via AlarmManager
 * - Check all contacts' outboxes
 * - Show notifications for new messages
 * - Go back to sleep
 *
 * Battery: ~1% duty cycle (vs 100% with continuous listeners)
 * Message delay: Up to 5 minutes when app is backgrounded
 */
class DnaMessengerService : Service() {
    companion object {
        private const val TAG = "DnaMessengerService"
        private const val NOTIFICATION_ID = 1001
        private const val POLL_ALARM_REQUEST_CODE = 2001

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
        private const val DEFAULT_POLL_INTERVAL_MS = 1 * 60 * 1000L  // 1 minute default

        // Configurable poll interval (can be changed via setPollInterval)
        @Volatile
        private var pollIntervalMs: Long = DEFAULT_POLL_INTERVAL_MS

        /**
         * Set poll interval in minutes. Called from Flutter via method channel.
         */
        fun setPollInterval(minutes: Int) {
            pollIntervalMs = minutes * 60 * 1000L
            android.util.Log.i(TAG, "Poll interval set to $minutes minutes")
            // Service instance will pick up new interval on next alarm schedule
        }
        private const val WAKELOCK_TIMEOUT_MS = 30 * 1000L   // 30 seconds (per check only)
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 2000L  // 2 seconds debounce

        @Volatile
        private var isRunning = false

        @Volatile
        private var flutterActive = false

        fun isServiceRunning(): Boolean = isRunning

        // Reference to service instance for triggering checks
        @Volatile
        private var serviceInstance: DnaMessengerService? = null

        /**
         * Set whether Flutter is active (in foreground).
         * When Flutter is active, service pauses polling (Flutter handles messaging).
         * When Flutter becomes inactive, service resumes polling.
         */
        /**
         * Set whether Flutter is active (in foreground).
         * When Flutter is active, service pauses polling (Flutter handles messaging).
         * When Flutter becomes inactive, service resumes polling.
         *
         * v0.100.89: Engine release moved to background thread to prevent UI freeze.
         * Previously, engineLock.lock() blocked the UI thread while waiting for
         * performMessageCheck() to complete (could take 2-5+ seconds), causing ANR.
         */
        fun setFlutterActive(active: Boolean) {
            val wasActive = flutterActive
            flutterActive = active
            android.util.Log.i(TAG, "Flutter active: $active (was: $wasActive)")

            if (active && !wasActive) {
                // Flutter taking over - release service's engine on BACKGROUND thread
                // v0.100.89: Moved to background thread to prevent UI freeze/ANR
                // v0.100.90: CORE FIX - signal shutdown BEFORE acquiring lock!
                // This makes ongoing C operations abort early, releasing the lock quickly.
                // Previously, we waited for ongoing DHT operations (2-5+ seconds).
                // Now they abort immediately when they see shutdown_requested=true.
                if (libraryLoaded) {
                    android.util.Log.i(TAG, "Signaling service engine to abort operations...")
                    nativeRequestShutdown()  // Sets shutdown_requested=true in C
                }

                // Now acquire lock on background thread - should be fast since ops are aborting
                Thread {
                    android.util.Log.i(TAG, "Flutter taking over - waiting for engine lock (background)...")
                    try {
                        engineLock.lock()
                        try {
                            // Double-check Flutter is still active (might have gone away during wait)
                            if (libraryLoaded && flutterActive) {
                                android.util.Log.i(TAG, "Releasing service engine for Flutter")
                                nativeReleaseEngine()
                                android.util.Log.i(TAG, "Service engine released for Flutter")
                            } else {
                                android.util.Log.i(TAG, "Skipping engine release - Flutter no longer active")
                            }
                        } finally {
                            engineLock.unlock()
                        }
                    } catch (e: Exception) {
                        android.util.Log.e(TAG, "Failed to release engine: ${e.message}")
                    }
                }.start()
            } else if (!active && wasActive) {
                // Flutter going away - service should take over
                android.util.Log.i(TAG, "Flutter inactive - service taking over")
                serviceInstance?.performMessageCheckAsync()
            }
        }

        /**
         * Direct DHT reinit via JNI.
         * Called when network changes while app is backgrounded.
         * Returns: 0 success, -1 DHT not initialized, -2 reinit failed
         */
        @JvmStatic
        external fun nativeReinitDht(): Int

        /**
         * Initialize engine if not already done.
         * Returns: true if engine is ready
         */
        @JvmStatic
        external fun nativeEnsureEngine(dataDir: String): Boolean

        /**
         * Check if identity is already loaded.
         */
        @JvmStatic
        external fun nativeIsIdentityLoaded(): Boolean

        /**
         * Load identity with minimal initialization (DHT only).
         * Returns: 0 on success, -117 if identity locked, other negative on error
         */
        @JvmStatic
        external fun nativeLoadIdentityMinimalSync(fingerprint: String): Int

        /**
         * Check if identity lock is held by Flutter.
         */
        @JvmStatic
        external fun nativeIsIdentityLocked(dataDir: String): Boolean

        /**
         * Release service's engine for Flutter takeover.
         */
        @JvmStatic
        external fun nativeReleaseEngine()

        /**
         * Request engine shutdown without destroying (v0.6.115+)
         *
         * Sets shutdown_requested flag so ongoing operations abort early.
         * Call this BEFORE acquiring engineLock so that nativeCheckOfflineMessages()
         * aborts quickly and releases the lock.
         */
        @JvmStatic
        external fun nativeRequestShutdown()

        /**
         * Check all contacts' outboxes for offline messages (v0.100.20+)
         * Synchronous polling function - replaces continuous listeners.
         * Returns: 0 on success, negative on error
         */
        @JvmStatic
        external fun nativeCheckOfflineMessages(): Int

        // Error code for identity lock held by another process
        private const val ERROR_IDENTITY_LOCKED = -117

        /**
         * v0.6.105: Lock to prevent race between engine release and engine use.
         *
         * Problem: nativeReleaseEngine() can be called from main thread (in setFlutterActive)
         * while performMessageCheck() is running on background thread. This causes
         * use-after-free crash when engine is destroyed mid-operation.
         *
         * Solution: Use a lock to serialize access. nativeReleaseEngine() waits for
         * any ongoing nativeCheckOfflineMessages() to complete before destroying engine.
         */
        private val engineLock = java.util.concurrent.locks.ReentrantLock()
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetworkChangeTime: Long = 0
    private var currentNetworkId: String? = null
    private var hadPreviousNetwork: Boolean = false

    override fun onCreate() {
        super.onCreate()
        android.util.Log.i(TAG, "Service created")
        createNotificationChannel()
        isRunning = true
        serviceInstance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: "START"
        android.util.Log.i(TAG, "onStartCommand: action=$action")

        when (action) {
            "START" -> startForegroundService()
            "STOP" -> stopForegroundService()
            "POLL" -> performMessageCheckAsync()  // Alarm triggered
        }

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        android.util.Log.i(TAG, "Service destroyed")
        isRunning = false
        serviceInstance = null
        cancelPollAlarm()
        releaseWakeLock()
        unregisterNetworkCallback()

        // v0.6.108: Release engine if service owns it (Flutter not active)
        // This ensures identity lock is released even if service is killed by Android
        if (libraryLoaded && !flutterActive) {
            try {
                engineLock.lock()
                try {
                    android.util.Log.i(TAG, "Releasing service engine on destroy")
                    nativeReleaseEngine()
                    android.util.Log.i(TAG, "Service engine released on destroy")
                } finally {
                    engineLock.unlock()
                }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Failed to release engine on destroy: ${e.message}")
            }
        }

        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        android.util.Log.i(TAG, "Task removed - service continues running")

        // Only continue if notifications are enabled
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        val notificationsEnabled = prefs.getBoolean("flutter.notifications_enabled", true)

        if (notificationsEnabled) {
            // Re-post the foreground notification
            try {
                val notification = createNotification("Background service active")
                val notificationManager = getSystemService(NotificationManager::class.java)
                notificationManager.notify(NOTIFICATION_ID, notification)
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Failed to re-post notification: ${e.message}")
            }
        }

        super.onTaskRemoved(rootIntent)
    }

    private fun startForegroundService() {
        android.util.Log.i(TAG, "Starting foreground service (polling mode)")

        createNotificationChannel()

        // Check notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasPermission = checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
            if (!hasPermission) {
                android.util.Log.w(TAG, "POST_NOTIFICATIONS permission not granted")
            }
        }

        val notification = createNotification("Background service active")

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            android.util.Log.i(TAG, "startForeground() called successfully")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "startForeground() failed: ${e.message}")
        }

        registerNetworkCallback()

        // Initialize notification helper if needed
        if (MainActivity.notificationHelper == null) {
            MainActivity.initNotificationHelper(this)
        }

        // Schedule first poll and do an immediate check
        schedulePollAlarm()
        performMessageCheckAsync()
    }

    private fun stopForegroundService() {
        android.util.Log.i(TAG, "Stopping foreground service")

        cancelPollAlarm()
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

    // ========== POLLING ==========

    /**
     * Schedule the next poll alarm.
     * Uses exact alarms if permitted, falls back to inexact on Android 12+.
     */
    private fun schedulePollAlarm() {
        val alarmManager = getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(this, DnaMessengerService::class.java).apply {
            action = "POLL"
        }
        val pendingIntent = PendingIntent.getService(
            this, POLL_ALARM_REQUEST_CODE, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val triggerTime = System.currentTimeMillis() + pollIntervalMs

        // Android 12+ requires SCHEDULE_EXACT_ALARM permission for exact alarms
        // Fall back to inexact if not granted (may delay up to 10 min in Doze)
        val canScheduleExact = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                alarmManager.canScheduleExactAlarms()
            } else {
                true
            }
        } catch (e: Exception) {
            android.util.Log.w(TAG, "canScheduleExactAlarms() failed: ${e.message}")
            false
        }

        android.util.Log.d(TAG, "canScheduleExact=$canScheduleExact, SDK=${Build.VERSION.SDK_INT}")

        try {
            if (canScheduleExact && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                alarmManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
                android.util.Log.d(TAG, "Poll alarm scheduled (exact) for ${pollIntervalMs / 1000}s")
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                alarmManager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
                android.util.Log.d(TAG, "Poll alarm scheduled (inexact) for ${pollIntervalMs / 1000}s")
            } else {
                alarmManager.set(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
                android.util.Log.d(TAG, "Poll alarm scheduled for ${pollIntervalMs / 1000}s")
            }
        } catch (e: SecurityException) {
            // Fall back to inexact alarm if exact fails
            android.util.Log.w(TAG, "Exact alarm failed, falling back to inexact: ${e.message}")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                alarmManager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
                android.util.Log.d(TAG, "Poll alarm scheduled (inexact fallback) for ${pollIntervalMs / 1000}s")
            } else {
                alarmManager.set(AlarmManager.RTC_WAKEUP, triggerTime, pendingIntent)
            }
        }
    }

    private fun cancelPollAlarm() {
        val alarmManager = getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(this, DnaMessengerService::class.java).apply {
            action = "POLL"
        }
        val pendingIntent = PendingIntent.getService(
            this, POLL_ALARM_REQUEST_CODE, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        alarmManager.cancel(pendingIntent)
        android.util.Log.d(TAG, "Poll alarm cancelled")
    }

    /**
     * Async wrapper for message check - runs on background thread.
     */
    fun performMessageCheckAsync() {
        Thread {
            performMessageCheck()
        }.start()
    }

    /**
     * Main polling function - called every N minutes (configurable).
     * Acquires short wakelock, checks messages, releases wakelock.
     *
     * v0.100.64+: When Flutter has the engine paused, we poll directly on
     * the paused engine via nativeCheckOfflineMessages() which uses the
     * global g_engine pointer (still valid when paused).
     *
     * v0.6.105: Acquires engineLock to prevent race with setFlutterActive().
     * This ensures nativeReleaseEngine() waits for this check to complete.
     */
    private fun performMessageCheck() {
        if (!libraryLoaded) {
            android.util.Log.e(TAG, "[POLL] Native library not loaded")
            schedulePollAlarm()
            return
        }

        // Skip if Flutter is active (in foreground - Flutter handles messaging)
        if (flutterActive) {
            android.util.Log.d(TAG, "[POLL] Skipped - Flutter active")
            schedulePollAlarm()
            return
        }

        android.util.Log.i(TAG, "[POLL] Starting message check...")
        val startTime = System.currentTimeMillis()

        // Acquire short wakelock for the check
        acquireWakeLock()

        // v0.6.105: Acquire engine lock to prevent race with setFlutterActive()
        // Use tryLock to avoid blocking forever if Flutter is releasing engine
        val gotLock = engineLock.tryLock(5, java.util.concurrent.TimeUnit.SECONDS)
        if (!gotLock) {
            android.util.Log.w(TAG, "[POLL] Couldn't acquire engine lock - Flutter may be taking over")
            releaseWakeLock()
            schedulePollAlarm()
            return
        }

        try {
            // Double-check Flutter didn't become active while we waited for lock
            if (flutterActive) {
                android.util.Log.d(TAG, "[POLL] Aborted - Flutter became active")
                return
            }

            val dataDir = filesDir.absolutePath + "/dna_messenger"

            // Check if Flutter has the engine paused (holding the lock)
            if (nativeIsIdentityLocked(dataDir)) {
                // v0.100.64+: Flutter engine is paused - poll directly on it
                // nativeCheckOfflineMessages() uses global g_engine which is still valid
                android.util.Log.i(TAG, "[POLL] Flutter paused - polling on paused engine")
                val result = nativeCheckOfflineMessages()
                val elapsed = System.currentTimeMillis() - startTime

                if (result >= 0) {
                    android.util.Log.i(TAG, "[POLL] Paused engine check completed in ${elapsed}ms (result=$result)")
                } else {
                    android.util.Log.e(TAG, "[POLL] Paused engine check failed in ${elapsed}ms (error=$result)")
                }
                return
            }

            // Flutter doesn't have the lock - ensure our own identity is loaded
            if (!ensureIdentityForCheck()) {
                android.util.Log.w(TAG, "[POLL] Cannot check - identity not available")
                return
            }

            // Check offline messages
            val result = nativeCheckOfflineMessages()
            val elapsed = System.currentTimeMillis() - startTime

            if (result >= 0) {
                android.util.Log.i(TAG, "[POLL] Check completed in ${elapsed}ms (result=$result)")
            } else {
                android.util.Log.e(TAG, "[POLL] Check failed in ${elapsed}ms (error=$result)")
            }

        } catch (e: Exception) {
            android.util.Log.e(TAG, "[POLL] Error: ${e.message}")
        } finally {
            engineLock.unlock()
            releaseWakeLock()
            schedulePollAlarm()
        }
    }

    /**
     * Ensure identity is loaded for message check.
     * Returns true if ready to check, false if cannot proceed.
     */
    private fun ensureIdentityForCheck(): Boolean {
        // Already loaded?
        if (nativeIsIdentityLoaded()) {
            return true
        }

        // Get fingerprint from SharedPreferences
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        val fingerprint = prefs.getString("flutter.identity_fingerprint", null)
        if (fingerprint.isNullOrEmpty()) {
            android.util.Log.d(TAG, "[POLL] No stored fingerprint")
            return false
        }

        val dataDir = filesDir.absolutePath + "/dna_messenger"

        // Check if Flutter has the lock
        if (nativeIsIdentityLocked(dataDir)) {
            android.util.Log.d(TAG, "[POLL] Identity locked by Flutter")
            return false
        }

        // Ensure engine
        if (!nativeEnsureEngine(dataDir)) {
            android.util.Log.e(TAG, "[POLL] Failed to ensure engine")
            return false
        }

        // Load identity (minimal mode - DHT only, no listeners)
        android.util.Log.i(TAG, "[POLL] Loading identity: ${fingerprint.take(16)}...")
        val result = nativeLoadIdentityMinimalSync(fingerprint)

        return when (result) {
            0 -> {
                android.util.Log.i(TAG, "[POLL] Identity loaded successfully")
                true
            }
            ERROR_IDENTITY_LOCKED -> {
                android.util.Log.w(TAG, "[POLL] Identity locked during load")
                nativeReleaseEngine()
                false
            }
            else -> {
                android.util.Log.e(TAG, "[POLL] Identity load failed: $result")
                false
            }
        }
    }

    // ========== WAKELOCK ==========

    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "DnaMessenger:PollWakeLock"
            )
        }
        wakeLock?.let {
            if (!it.isHeld) {
                it.acquire(WAKELOCK_TIMEOUT_MS)
                android.util.Log.d(TAG, "WakeLock acquired (${WAKELOCK_TIMEOUT_MS / 1000}s timeout)")
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
    }

    // ========== NOTIFICATION ==========

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(NotificationManager::class.java)

            val existingChannel = notificationManager.getNotificationChannel(CHANNEL_ID)
            if (existingChannel != null) {
                return
            }

            val channel = NotificationChannel(
                CHANNEL_ID,
                "DNA Messenger Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Background message checking"
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
            android.util.Log.i(TAG, "Created notification channel")
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
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    // ========== NETWORK MONITORING ==========

    private fun registerNetworkCallback() {
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val networkId = network.toString()
                android.util.Log.i(TAG, "Network available: $networkId")

                // Trigger check on network change (not initial connect)
                val shouldCheck = when {
                    currentNetworkId != null && currentNetworkId != networkId -> true
                    hadPreviousNetwork && currentNetworkId == null -> true
                    else -> false
                }

                if (shouldCheck) {
                    handleNetworkChange(networkId)
                }

                currentNetworkId = networkId
                hadPreviousNetwork = true
            }

            override fun onLost(network: Network) {
                val networkId = network.toString()
                android.util.Log.i(TAG, "Network lost: $networkId")
                if (currentNetworkId == networkId) {
                    currentNetworkId = null
                }
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

        // Debounce rapid network changes
        if (now - lastNetworkChangeTime < NETWORK_CHANGE_DEBOUNCE_MS) {
            android.util.Log.d(TAG, "Network change debounced")
            return
        }
        lastNetworkChangeTime = now

        android.util.Log.i(TAG, "Network changed - triggering immediate check")

        // Reinit DHT and check messages on network change
        Thread {
            if (!libraryLoaded || flutterActive) return@Thread

            try {
                // Reinit DHT for new network
                if (nativeIsIdentityLoaded()) {
                    val result = nativeReinitDht()
                    android.util.Log.i(TAG, "DHT reinit result: $result")
                }

                // Small delay for DHT to connect
                Thread.sleep(2000)

                // Check messages
                performMessageCheck()
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Network change handling error: ${e.message}")
            }
        }.start()
    }
}
