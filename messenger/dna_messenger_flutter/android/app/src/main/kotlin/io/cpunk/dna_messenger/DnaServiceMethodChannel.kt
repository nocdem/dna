package io.cpunk.dna_messenger

import android.content.Context
import android.content.Intent
import android.os.Build
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
 *
 * Phase 14: Android background execution for reliable DHT-only messaging.
 */
class DnaServiceMethodChannel(
    private val context: Context,
    flutterEngine: FlutterEngine
) {
    companion object {
        const val CHANNEL_NAME = "io.cpunk.dna_messenger/service"
        private const val TAG = "DnaServiceMethodChannel"
    }

    private val channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL_NAME)

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
                else -> {
                    result.notImplemented()
                }
            }
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
}
