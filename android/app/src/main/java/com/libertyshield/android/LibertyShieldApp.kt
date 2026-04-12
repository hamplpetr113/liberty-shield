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
import android.os.Build
import android.os.StrictMode
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

@HiltAndroidApp
class LibertyShieldApp : Application(), Configuration.Provider {

    @Inject
    lateinit var workerFactory: HiltWorkerFactory

    override fun onCreate() {
        super.onCreate()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            enableStrictModeInDebug()
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
