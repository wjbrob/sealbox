package dev.sealbox.sealbox_app

import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// FlutterFragmentActivity: local_auth's BiometricPrompt needs a FragmentActivity (app lock).
class MainActivity : FlutterFragmentActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // The recovery-phrase screen blocks screenshots and the recents thumbnail while it is
        // open (FLAG_SECURE); lib/src/platform/secure_screen.dart.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "sealbox/secure_screen")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "setSecure" -> {
                        val on = call.arguments as? Boolean ?: false
                        runOnUiThread {
                            if (on) {
                                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            } else {
                                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            }
                        }
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }
}
