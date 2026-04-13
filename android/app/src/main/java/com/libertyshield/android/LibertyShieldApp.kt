/*
 * Threat model: Application entry point.
 * Risk: DI graph initialization failure → app unusable.
 * Mitigation: Hilt crash on startup is preferable to silent misconfiguration.
 *
 * Risk: StrictMode false positives in release → only enabled in debug builds.
 * Risk: WorkManager re-initialization → idempotent by design.
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
        try {
            super.onCreate()
            // Create notification channel BEFORE anything else that may start a service.
            // This must happen in Application.onCreate() so the channel exists even if the
            // service is started by BootReceiver before the Activity is ever opened.
            createNotificationChannels()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                enableStrictModeInDebug()
            }
        } catch (e: Exception) {
            Log.e(TAG, "CRASH in Application.onCreate: ${e.message}", e)
            throw e
        }
    }

    /**
     * Creates all notification channels for the app.
     * Safe to call multiple times — creating an existing channel is a no-op.
     * Must be called before any startForeground() call.
     */
    private fun createNotificationChannels() {
        // NotificationChannel requires API 26 which is our minSdk, but the guard
        // is kept for clarity and in case the constant ever changes.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
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
    }

    /**
     * Provide WorkManager configuration with Hilt worker factory.
     * This allows @HiltWorker injection into CoroutineWorker subclasses.
     */
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
                .penaltyLog()
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
