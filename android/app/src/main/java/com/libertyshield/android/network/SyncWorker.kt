/*
 * Threat model: Reliable sync layer.
 * Risk: Network unavailable → events queued in Room, retried by WorkManager
 * Risk: API auth failure → logged, not retried (avoids lockout)
 * Risk: Partial sync → each event marked synced individually after successful upload
 * Risk: Worker injection failure → HiltWorker annotation + HiltWorkerFactory in App
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
import com.libertyshield.android.data.repository.EventRepository
import com.libertyshield.android.data.prefs.SecurePrefs
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

        /**
         * Enqueues a periodic sync job that runs every 15 minutes when network is available.
         * Uses KEEP policy — if a job is already queued, it won't be replaced.
         */
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

        val apiKey = securePrefs.getApiKey()
        if (apiKey.isEmpty()) {
            Log.w(TAG, "API key not configured — skipping sync")
            return Result.success() // Not a retryable failure
        }

        val authHeader = "Bearer $apiKey"

        return try {
            val unsyncedEvents = eventRepository.getUnsyncedEvents()

            if (unsyncedEvents.isEmpty()) {
                Log.d(TAG, "No unsynced events — nothing to do")
                return Result.success()
            }

            Log.i(TAG, "Syncing ${unsyncedEvents.size} events in batches of $BATCH_SIZE")

            var anyFailure = false

            for (batch in unsyncedEvents.chunked(BATCH_SIZE)) {
                for (event in batch) {
                    val payload = SensorEventPayload(
                        deviceId = event.deviceId,
                        sensor = event.sensor.name.lowercase(),
                        appPackage = event.packageName,
                        appLabel = event.appLabel,
                        action = event.action,
                        riskScore = event.riskScore,
                        misdirectionActive = event.misdirectionActive,
                        ts = event.timestamp
                    )

                    try {
                        val response = apiService.reportEvent(authHeader, payload)

                        when {
                            response.isSuccessful -> {
                                // Mark this event synced immediately
                                eventRepository.markSynced(listOf(event.id))
                                Log.v(TAG, "Event ${event.id} synced successfully")
                            }
                            response.code() == 401 -> {
                                Log.e(TAG, "Auth failure (401) — aborting sync to avoid lockout")
                                return Result.failure()
                            }
                            response.code() in 500..599 -> {
                                Log.w(TAG, "Server error ${response.code()} for event ${event.id}")
                                anyFailure = true
                            }
                            else -> {
                                Log.w(TAG, "Unexpected response ${response.code()} for event ${event.id}")
                                anyFailure = true
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Network error syncing event ${event.id}: ${e.message}")
                        anyFailure = true
                    }
                }
            }

            if (anyFailure) {
                Log.w(TAG, "Some events failed to sync — scheduling retry")
                Result.retry()
            } else {
                Log.i(TAG, "All events synced successfully")
                Result.success()
            }

        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error in SyncWorker: ${e.message}", e)
            Result.retry()
        }
    }
}
