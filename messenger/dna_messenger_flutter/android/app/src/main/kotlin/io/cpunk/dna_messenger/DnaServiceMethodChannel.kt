package io.cpunk.dna_messenger

import android.Manifest
import android.app.Activity
import android.app.AlarmManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * MethodChannel handler for DNA Messenger ForegroundService
 *
 * Provides Flutter communication with the native service:
 * - startService: Start the foreground service
 * - stopService: Stop the foreground service
 * - isServiceRunning: Check if service is running
 * - pollNow: Trigger immediate offline message poll
 * - setPollInterval: Set poll interval in minutes (v0.100.64+)
 *
 * Phase 14: Android background execution for reliable DHT-only messaging.
 */
class DnaServiceMethodChannel(
    private val activity: Activity,
    flutterEngine: FlutterEngine
) {
    companion object {
        const val CHANNEL_NAME = "io.cpunk.dna_messenger/service"
        private const val TAG = "DnaServiceMethodChannel"
        private const val NOTIFICATION_PERMISSION_REQUEST_CODE = 1001
    }

    private val context: Context = activity
    private val channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL_NAME)
    private var pendingPermissionResult: MethodChannel.Result? = null

    init {
        channel.setMethodCallHandler { call, result ->
            android.util.Log.d(TAG, "Method call: ${call.method}")
            when (call.method) {
                "startService" -> {
                    startService()
                    result.success(true)
                }
                "stopService" -> {
                    stopService()
                    result.success(true)
                }
                "isServiceRunning" -> {
                    result.success(DnaMessengerService.isServiceRunning())
                }
                "pollNow" -> {
                    pollNow()
                    result.success(true)
                }
                "requestNotificationPermission" -> {
                    requestNotificationPermission(result)
                }
                "hasNotificationPermission" -> {
                    result.success(hasNotificationPermission())
                }
                "setFlutterActive" -> {
                    val active = call.argument<Boolean>("active") ?: false
                    setFlutterActive(active)
                    result.success(null)
                }
                "canScheduleExactAlarms" -> {
                    result.success(canScheduleExactAlarms())
                }
                "requestExactAlarmPermission" -> {
                    requestExactAlarmPermission()
                    result.success(null)
                }
                "setPollInterval" -> {
                    val minutes = call.argument<Int>("minutes") ?: 5
                    setPollInterval(minutes)
                    result.success(null)
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
    }

    /**
     * Check if notification permission is granted
     */
    private fun hasNotificationPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            // Pre-Android 13 doesn't need explicit permission
            true
        }
    }

    /**
     * Request notification permission (Android 13+)
     */
    private fun requestNotificationPermission(result: MethodChannel.Result) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (hasNotificationPermission()) {
                result.success(true)
            } else {
                pendingPermissionResult = result
                ActivityCompat.requestPermissions(
                    activity,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    NOTIFICATION_PERMISSION_REQUEST_CODE
                )
            }
        } else {
            // Pre-Android 13 doesn't need explicit permission
            result.success(true)
        }
    }

    /**
     * Handle permission request result from Activity
     */
    fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        if (requestCode == NOTIFICATION_PERMISSION_REQUEST_CODE) {
            val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
            pendingPermissionResult?.success(granted)
            pendingPermissionResult = null
        }
    }

    private fun startService() {
        android.util.Log.i(TAG, "Starting service")
        val intent = Intent(context, DnaMessengerService::class.java).apply {
            action = "START"
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    private fun stopService() {
        android.util.Log.i(TAG, "Stopping service")
        val intent = Intent(context, DnaMessengerService::class.java).apply {
            action = "STOP"
        }
        context.startService(intent)
    }

    private fun pollNow() {
        android.util.Log.i(TAG, "Requesting immediate poll")
        val intent = Intent(context, DnaMessengerService::class.java).apply {
            action = "POLL_NOW"
        }
        context.startService(intent)
    }

    private fun setFlutterActive(active: Boolean) {
        android.util.Log.i(TAG, "Setting Flutter active: $active")
        DnaMessengerService.setFlutterActive(active)
    }

    /**
     * Set poll interval in minutes (v0.100.64+)
     */
    private fun setPollInterval(minutes: Int) {
        android.util.Log.i(TAG, "Setting poll interval: $minutes minutes")
        DnaMessengerService.setPollInterval(minutes)
    }

    /**
     * Check if exact alarms can be scheduled (Android 12+)
     * Returns true on older Android versions or if permission is granted
     */
    private fun canScheduleExactAlarms(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            alarmManager.canScheduleExactAlarms()
        } else {
            true
        }
    }

    /**
     * Request exact alarm permission (Android 12+)
     * Opens system settings - user must manually enable
     */
    private fun requestExactAlarmPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                val intent = Intent(android.provider.Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                context.startActivity(intent)
            } catch (e: Exception) {
                android.util.Log.w(TAG, "Could not open alarm settings: ${e.message}")
            }
        }
    }

    /**
     * Notify Flutter about new messages received in background
     * Call this from service when messages are detected
     */
    fun notifyNewMessages(count: Int, senderName: String?) {
        android.util.Log.i(TAG, "Notifying Flutter: $count new messages from $senderName")
        channel.invokeMethod("onNewMessages", mapOf(
            "count" to count,
            "senderName" to senderName
        ))
    }

    /**
     * Notify Flutter about network connectivity change
     * Call this when network changes (WiFi <-> Cellular) to trigger DHT reinit
     */
    fun notifyNetworkChanged() {
        android.util.Log.i(TAG, "Notifying Flutter: network changed, DHT reinit needed")
        channel.invokeMethod("onNetworkChanged", null)
    }
}
