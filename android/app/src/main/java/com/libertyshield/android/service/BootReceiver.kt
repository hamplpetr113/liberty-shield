/*
 * Threat model: Persistence layer.
 * Ensures Liberty Shield restarts after device reboot — but ONLY if the user
 * previously activated protection. We never auto-start without consent.
 *
 * Risk: BOOT_COMPLETED can be spoofed by malicious apps.
 * Mitigation: We only start our own service; no external data consumed.
 *
 * Risk: Starting service on boot when runtime permissions were revoked
 *       (auto-revoke after 90 days, or user revoke between reboots).
 * Mitigation: startForegroundSafely() in SensorMonitorService handles missing permissions
 *   gracefully (starts as basic foreground service without sensor types). We still start
 *   the service so it can log the PERMISSION_MISSING event and remain visible in the UI.
 *
 * Risk: Starting service before user unlocks screen (LOCKED_BOOT_COMPLETED).
 * Mitigation: startForegroundService() works before first unlock.
 */
package com.libertyshield.android.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.libertyshield.android.data.ShieldPreferences
import com.libertyshield.android.network.SyncWorker
import java.util.concurrent.TimeUnit

class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return

        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != "android.intent.action.LOCKED_BOOT_COMPLETED") {
            Log.w(TAG, "Unexpected action: $action — ignoring")
            return
        }

        Log.i(TAG, "Boot completed ($action)")

        if (!ShieldPreferences.isShieldEnabled(context)) {
            Log.i(TAG, "Shield is disabled — not starting service on boot")
            return
        }

        Log.i(TAG, "Shield is enabled — starting SensorMonitorService")

        // Start the service unconditionally when shield is enabled.
        // SensorMonitorService.startForegroundSafely() handles the case where permissions
        // were revoked between reboots — it starts in degraded mode and logs the state.
        // This is preferable to silently failing to restart.
        try {
            val serviceIntent = SensorMonitorService.startIntent(context)
            ContextCompat.startForegroundService(context, serviceIntent)
            Log.i(TAG, "SensorMonitorService start requested successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start SensorMonitorService on boot: ${e.message}", e)
        }

        try {
            enqueueSyncWorker(context)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enqueue SyncWorker on boot: ${e.message}", e)
        }
    }

    private fun enqueueSyncWorker(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val syncRequest = PeriodicWorkRequestBuilder<SyncWorker>(
            15, TimeUnit.MINUTES
        )
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            SyncWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            syncRequest
        )

        Log.i(TAG, "SyncWorker periodic work enqueued (15 min, NETWORK_CONNECTED)")
    }
}
