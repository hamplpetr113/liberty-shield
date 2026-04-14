/*
 * Threat model: Application entry point.
 * Risk: DI graph initialization failure → app unusable.
 * Mitigation: Hilt crash on startup is preferable to silent misconfiguration.
 *
 * Risk: StrictMode false positives in release → only enabled in debug builds.
 * Risk: WorkManager re-initialization → idempotent by design.
 * Risk: SQLiteDatabase.loadLibs() failure → logged but not re-thrown; app can still
 *       open UI and show diagnostics even if database is unavailable.
 */
package com.libertyshield.android

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import android.os.StrictMode
import android.util.Log
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import dagger.hilt.android.HiltAndroidApp
import net.sqlcipher.database.SQLiteDatabase
import javax.inject.Inject

@HiltAndroidApp
class LibertyShieldApp : Application(), Configuration.Provider {

    @Inject
    lateinit var workerFactory: HiltWorkerFactory

    companion object {
        private const val TAG = "LibertyShieldApp"
        const val NOTIFICATION_CHANNEL_ID = "liberty_shield_channel"
    }

    override fun onCreate() {
        super.onCreate()

        // Load SQLCipher native libs FIRST — must happen before any SupportFactory
        // instantiation in DatabaseModule. On exotic devices this can fail (missing .so),
        // in which case we log the error but do NOT rethrow — the app can still show UI
        // and diagnostics even if the encrypted database is unavailable.
        try {
            SQLiteDatabase.loadLibs(this)
            Log.d(TAG, "SQLCipher native libs loaded successfully")
        } catch (e: Throwable) {
            Log.e(TAG, "SQLCipher loadLibs() FAILED — encrypted database will be unavailable: ${e.message}", e)
            // Continue; DatabaseModule will fail when first accessed and show error in Debug screen.
        }

        // Create notification channel BEFORE anything else that may start a service.
        // This must happen in Application.onCreate() so the channel exists even if the
        // service is started by BootReceiver before the Activity is ever opened.
        try {
            createNotificationChannels()
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to create notification channels: ${e.message}", e)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            enableStrictModeInDebug()
        }
    }

    private fun createNotificationChannels() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "Liberty Shield Protection",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Liberty Shield is actively protecting your device"
            setShowBadge(false)
            enableVibration(false)
            enableLights(false)
        }
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
        Log.d(TAG, "Notification channel created: $NOTIFICATION_CHANNEL_ID")
    }

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .setMinimumLoggingLevel(
                if (BuildConfig.DEBUG) android.util.Log.DEBUG
                else android.util.Log.ERROR
            )
            .build()

    private fun enableStrictModeInDebug() {
        if (!BuildConfig.DEBUG) return

        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder()
                .detectDiskReads()
                .detectDiskWrites()
                .detectNetwork()
                .penaltyLog()   // log-only; never penaltyDeath in case of false positives
                .build()
        )

        StrictMode.setVmPolicy(
            StrictMode.VmPolicy.Builder()
                .detectLeakedSqlLiteObjects()
                .detectLeakedClosableObjects()
                .detectActivityLeaks()
                .penaltyLog()
                .build()
        )
    }
}
