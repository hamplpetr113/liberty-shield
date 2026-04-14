/*
 * Threat model: Reliable sync layer.
 * Risk: Network unavailable → events queued in Room, retried by WorkManager
 * Risk: API auth failure → logged as SYNC_FAILED, not retried (avoids lockout)
 * Risk: Partial sync → each event marked synced individually after successful upload
 * Risk: Worker injection failure → HiltWorker annotation + HiltWorkerFactory in App
 * Risk: Starting foreground service from Worker context → NOT done here.
 *       SensorMonitorService is self-healing via START_STICKY; BootReceiver handles reboots.
 *       Attempting startForegroundService() from a non-foreground Worker throws
 *       ForegroundServiceStartNotAllowedException on Android 12+.
 */
package com.libertyshield.android.network

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.libertyshield.android.data.ShieldPreferences
import com.libertyshield.android.data.model.EventAction
import com.libertyshield.android.data.prefs.SecurePrefs
import com.libertyshield.android.data.repository.EventRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

@HiltWorker
class SyncWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted workerParams: WorkerParameters,
    private val eventRepository: EventRepository,
    private val apiService: ApiService,
    private val securePrefs: SecurePrefs
) : CoroutineWorker(context, workerParams) {

    companion object {
        private const val TAG = "SyncWorker"
        const val WORK_NAME = "liberty_shield_sync"
        private const val BATCH_SIZE = 50

        fun schedulePeriodicSync(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val request = PeriodicWorkRequestBuilder<SyncWorker>(
                15, TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
            Log.i(TAG, "Periodic sync scheduled (15 min interval, NETWORK_CONNECTED)")
        }
    }

    override suspend fun doWork(): Result {
        Log.d(TAG, "SyncWorker starting")

        // Config check — report as failure so the Debug screen shows the real state,
        // not a misleading "success" when nothing was actually attempted.
        val apiKey = securePrefs.getApiKey()
        if (apiKey.isEmpty()) {
            Log.w(TAG, "API key not configured — sync skipped. Set SENSOR_API_KEY in Settings.")
            ShieldPreferences.setLastSyncResult(
                applicationContext, success = false, eventCount = 0
            )
            // Use failure (not retry) — missing config is not a transient network error.
            return Result.failure()
        }

        val authHeader = "Bearer $apiKey"

        return try {
            val unsyncedEvents = eventRepository.getUnsyncedEvents()

            if (unsyncedEvents.isEmpty()) {
                Log.d(TAG, "No unsynced events — nothing to do")
                ShieldPreferences.setLastSyncResult(
                    applicationContext, success = true, eventCount = 0
                )
                return Result.success()
            }

            Log.i(TAG, "Syncing ${unsyncedEvents.size} events in batches of $BATCH_SIZE")

            var successCount = 0
            var anyFailure = false

            for (batch in unsyncedEvents.chunked(BATCH_SIZE)) {
                for (event in batch) {
                    val payload = SensorEventPayload(
                        deviceId           = event.deviceId,
                        sensor             = event.sensor.name.lowercase(),
                        appPackage         = event.packageName,
                        appLabel           = event.appLabel,
                        action             = event.action,
                        riskScore          = event.riskScore,
                        misdirectionActive = event.misdirectionActive,
                        ts                 = event.timestamp
                    )

                    try {
                        val response = apiService.reportEvent(authHeader, payload)

                        when {
                            response.isSuccessful -> {
                                eventRepository.markSynced(listOf(event.id))
                                successCount++
                                Log.v(TAG, "Event ${event.id} synced successfully")
                            }
                            response.code() == 401 -> {
                                Log.e(TAG, "Auth failure (401) — aborting sync to avoid lockout")
                                ShieldPreferences.setLastSyncResult(
                                    applicationContext, success = false, eventCount = successCount
                                )
                                return Result.failure()
                            }
                            response.code() in 500..599 -> {
                                Log.w(TAG, "Server error ${response.code()} for event ${event.id}")
                                anyFailure = true
                            }
                            else -> {
                                Log.w(TAG, "Unexpected ${response.code()} for event ${event.id}")
                                anyFailure = true
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Network error for event ${event.id}: ${e.message}")
                        anyFailure = true
                    }
                }
            }

            if (anyFailure) {
                Log.w(TAG, "Some events failed to sync ($successCount/${unsyncedEvents.size} succeeded) — scheduling retry")
                ShieldPreferences.setLastSyncResult(
                    applicationContext, success = false, eventCount = successCount
                )
                Result.retry()
            } else {
                Log.i(TAG, "All ${unsyncedEvents.size} events synced successfully")
                ShieldPreferences.setLastSyncResult(
                    applicationContext, success = true, eventCount = successCount
                )
                try {
                    eventRepository.logSystemEvent(
                        action    = EventAction.SYNC_SUCCESS,
                        label     = "Sync: $successCount events uploaded",
                        riskScore = 0
                    )
                } catch (e: Exception) {
                    Log.w(TAG, "Could not log SYNC_SUCCESS event: ${e.message}")
                }
                Result.success()
            }

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error in SyncWorker: ${e.message}", e)
            ShieldPreferences.setLastSyncResult(
                applicationContext, success = false, eventCount = 0
            )
            Result.retry()
        }
    }
}
