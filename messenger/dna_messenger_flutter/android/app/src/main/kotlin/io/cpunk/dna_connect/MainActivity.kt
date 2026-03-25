package io.cpunk.dna_connect

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream

/**
 * DNA Connect Main Activity
 *
 * Minimal activity: camera permission + CA certificate bundle copy + screen security.
 * No background service, no notifications — engine runs while app is open.
 */
class MainActivity : FlutterFragmentActivity() {
    companion object {
        private const val TAG = "MainActivity"
        private const val CAMERA_PERMISSION_REQUEST_CODE = 1003
        private const val CHANNEL = "io.cpunk.dna_connect/screen_security"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Copy CA bundle from assets to app data directory for curl SSL
        copyCACertificateBundle()

        // Request camera permission for QR scanner
        requestCameraPermissionIfNeeded()
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "enableSecureMode" -> {
                    window.setFlags(
                        WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE
                    )
                    result.success(null)
                }
                "disableSecureMode" -> {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
    }

    /**
     * Request camera permission if not already granted.
     * Ask early at startup so user doesn't get interrupted when opening QR scanner.
     */
    private fun requestCameraPermissionIfNeeded() {
        val hasPermission = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED

        if (hasPermission) {
            android.util.Log.d(TAG, "Camera permission already granted")
            return
        }

        android.util.Log.i(TAG, "Requesting camera permission at startup")
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.CAMERA),
            CAMERA_PERMISSION_REQUEST_CODE
        )
    }

    /**
     * Copy cacert.pem from assets to app's dna data directory.
     * This is required for curl to verify SSL certificates on Android.
     * Must match the path that Flutter uses: filesDir/dna/cacert.pem
     */
    private fun copyCACertificateBundle() {
        val dnaDir = File(filesDir, "dna")
        if (!dnaDir.exists()) {
            dnaDir.mkdirs()
        }

        val destFile = File(dnaDir, "cacert.pem")

        try {
            val assetSize = assets.open("cacert.pem").use { it.available() }
            if (destFile.exists() && destFile.length() == assetSize.toLong()) {
                return // Already up to date
            }
        } catch (e: Exception) {
            return // Asset doesn't exist
        }

        try {
            assets.open("cacert.pem").use { input ->
                FileOutputStream(destFile).use { output ->
                    input.copyTo(output)
                }
            }
            android.util.Log.i("DNA", "CA bundle copied to: ${destFile.absolutePath}")
        } catch (e: Exception) {
            android.util.Log.e("DNA", "Failed to copy CA bundle: ${e.message}")
        }
    }
}
