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
import androidx.core.app.NotificationCompat

/**
 * DNA Messenger Foreground Service (v0.101.25+)
 *
 * Simplified: process keep-alive ONLY. Engine stays alive via pause/resume pattern.
 * No polling, no engine management, no wakelocks, no AlarmManager.
 *
 * Background notifications come via JNI callback (g_android_notification_cb) because
 * the C engine's Nodus TCP connection and DHT listeners remain active when paused.
 *
 * This service exists solely to prevent Android from killing the process.
 * Network monitoring triggers DHT reinit when connectivity changes.
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
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 2000L

        @Volatile
        private var isRunning = false

        @Volatile
        private var flutterPaused = false

        fun isServiceRunning(): Boolean = isRunning

        // Reference to service instance
        @Volatile
        private var serviceInstance: DnaMessengerService? = null

        /**
         * Set whether Flutter is paused (for notification clearing logic only).
         * When Flutter resumes, it clears notifications itself via clearNotifications.
         */
        fun setFlutterPaused(paused: Boolean) {
            flutterPaused = paused
            svcLog("setFlutterPaused: $paused")
        }

        /**
         * Direct DHT reinit via JNI.
         * Called when network changes while app is backgrounded.
         */
        @JvmStatic
        external fun nativeReinitDht(): Int

        /**
         * Check if Flutter's engine is alive (g_engine != NULL).
         * Used by service to detect if OS killed the process and engine is gone.
         */
        @JvmStatic
        external fun nativeIsEngineAlive(): Boolean

        /**
         * Initialize engine if not already done (fallback for OS-kill case).
         */
        @JvmStatic
        external fun nativeEnsureEngine(dataDir: String): Boolean

        /**
         * Load identity with FULL initialization (fallback for OS-kill case).
         * Sets up TCP listeners so engine gets instant push.
         */
        @JvmStatic
        external fun nativeLoadIdentitySync(fingerprint: String): Int

        /**
         * Pause engine — stops presence heartbeat but keeps TCP + listeners alive.
         * Call after fallback restore so user doesn't appear "online" after swipe.
         */
        @JvmStatic
        external fun nativePauseEngine()

        /**
         * Check if identity is already loaded.
         */
        @JvmStatic
        external fun nativeIsIdentityLoaded(): Boolean

        /**
         * Log bridge - writes to dna.log + ring buffer (Debug Log screen)
         */
        @JvmStatic
        external fun nativeServiceLog(message: String)

        private fun svcLog(msg: String) {
            android.util.Log.i(TAG, msg)
            try {
                if (libraryLoaded) nativeServiceLog(msg)
            } catch (_: Exception) {}
        }
    }

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
        svcLog("onStartCommand: action=$action")

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
        serviceInstance = null
        unregisterNetworkCallback()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        svcLog("Task removed (swipe from recents)")

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
                svcLog("Failed to re-post notification: ${e.message}")
            }

            // Schedule a restart alarm as safety net (5s from now)
            try {
                val restartIntent = Intent(this, DnaMessengerService::class.java).apply {
                    action = "START"
                }
                val restartPi = PendingIntent.getService(
                    this, 2001, restartIntent,
                    PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
                )
                val alarmManager = getSystemService(Context.ALARM_SERVICE) as android.app.AlarmManager
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    alarmManager.setExactAndAllowWhileIdle(
                        android.app.AlarmManager.RTC_WAKEUP,
                        System.currentTimeMillis() + 5000,
                        restartPi
                    )
                } else {
                    alarmManager.set(android.app.AlarmManager.RTC_WAKEUP,
                        System.currentTimeMillis() + 5000, restartPi)
                }
                svcLog("Restart alarm scheduled in 5s")
            } catch (e: Exception) {
                svcLog("Failed to schedule restart alarm: ${e.message}")
            }

            // If engine was killed by OS, do a fallback poll
            if (libraryLoaded && !nativeIsEngineAlive()) {
                svcLog("Engine gone after swipe — restoring with listeners")
                Thread { performFallbackRestore() }.start()
            }
        }

        super.onTaskRemoved(rootIntent)
    }

    private fun startForegroundService() {
        android.util.Log.i(TAG, "Starting foreground service (keep-alive mode)")

        createNotificationChannel()

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
    }

    private fun stopForegroundService() {
        android.util.Log.i(TAG, "Stopping foreground service")

        unregisterNetworkCallback()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    // ========== FALLBACK: OS-KILL RECOVERY ==========

    /**
     * Fallback for when OS kills the process and engine is gone.
     * This is the ONLY case where the service creates its own engine.
     * Creates engine → full identity load (with TCP listeners) → engine stays alive
     * getting instant push via JNI notification callback. When Flutter starts later,
     * it detects engine exists and takes it over.
     */
    private fun performFallbackRestore() {
        if (!libraryLoaded) return

        // Check if engine somehow came back (race with Flutter restart)
        if (nativeIsEngineAlive()) {
            svcLog("[FALLBACK] Engine is alive, skipping")
            return
        }

        svcLog("[FALLBACK] === Engine dead, creating fallback engine with listeners ===")

        // Ensure notification helper is registered (for JNI push callback)
        if (MainActivity.notificationHelper == null) {
            try {
                MainActivity.initNotificationHelper(this)
            } catch (e: Exception) {
                svcLog("[FALLBACK] WARN: Failed to init notification helper: ${e.message}")
            }
        }

        val dataDir = filesDir.absolutePath + "/dna_messenger"

        // Create engine
        if (!nativeEnsureEngine(dataDir)) {
            svcLog("[FALLBACK] FAIL: nativeEnsureEngine returned false")
            return
        }

        // Get fingerprint from SharedPreferences
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        val fingerprint = prefs.getString("flutter.identity_fingerprint", null)
        if (fingerprint.isNullOrEmpty()) {
            svcLog("[FALLBACK] FAIL: no fingerprint in SharedPreferences")
            return
        }

        // Full identity load — sets up TCP connection + DHT listeners + presence
        // Engine will receive instant push via JNI notification callback
        svcLog("[FALLBACK] Loading identity (full): ${fingerprint.take(16)}...")
        val result = nativeLoadIdentitySync(fingerprint)
        if (result != 0) {
            svcLog("[FALLBACK] FAIL: identity load error=$result")
            return
        }

        // Immediately pause — stops presence heartbeat (user shouldn't appear online
        // after swipe) but keeps TCP + listeners alive for instant push
        nativePauseEngine()

        svcLog("[FALLBACK] === Engine restored (paused) — TCP listeners active, presence off ===")
        // Engine stays alive in paused state — same as normal Flutter background
        // When Flutter starts, lifecycle_observer calls engine.resume()
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

                val shouldReinit = when {
                    currentNetworkId != null && currentNetworkId != networkId -> true
                    hadPreviousNetwork && currentNetworkId == null -> true
                    else -> false
                }

                if (shouldReinit) {
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

        if (now - lastNetworkChangeTime < NETWORK_CHANGE_DEBOUNCE_MS) {
            android.util.Log.d(TAG, "Network change debounced")
            return
        }
        lastNetworkChangeTime = now

        android.util.Log.i(TAG, "Network changed — triggering DHT reinit")

        Thread {
            if (!libraryLoaded) return@Thread

            try {
                if (nativeIsEngineAlive() && nativeIsIdentityLoaded()) {
                    val result = nativeReinitDht()
                    android.util.Log.i(TAG, "DHT reinit result: $result")
                }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Network change handling error: ${e.message}")
            }
        }.start()
    }
}
