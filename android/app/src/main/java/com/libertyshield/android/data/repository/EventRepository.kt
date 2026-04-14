/*
 * Threat model: Data access layer.
 * Single source of truth for all sensor events.
 * Risk: Concurrent writes → Room handles via transaction
 * Risk: Data loss on crash → Room writes are synchronous in transaction
 * Risk: Uncontrolled DB growth → caller should schedule periodic cleanup
 */
package com.libertyshield.android.data.repository

import android.util.Log
import com.libertyshield.android.data.db.SensorEventDao
import com.libertyshield.android.data.db.SensorEventEntity
import com.libertyshield.android.data.model.SensorEvent
import com.libertyshield.android.data.model.toDomain
import com.libertyshield.android.data.prefs.SecurePrefs
import com.libertyshield.android.engine.SensorType
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

// Package name used for all system/lifecycle events written by Liberty Shield itself.
private const val LS_PACKAGE = "com.libertyshield.android"

@Singleton
class EventRepository @Inject constructor(
    private val sensorEventDao: SensorEventDao,
    private val securePrefs: SecurePrefs
) {

    companion object {
        private const val TAG = "EventRepository"
    }

    /**
     * Inserts a new sensor event into the encrypted database.
     * Attaches the stable device ID from SecurePrefs.
     */
    suspend fun logEvent(
        packageName: String,
        appLabel: String,
        sensor: SensorType,
        action: String,
        riskScore: Int,
        misdirectionActive: Boolean
    ) {
        val entity = SensorEventEntity(
            packageName = packageName,
            appLabel = appLabel,
            sensor = sensor.name.lowercase(),
            action = action,
            riskScore = riskScore,
            misdirectionActive = misdirectionActive,
            synced = false,
            timestamp = System.currentTimeMillis(),
            deviceId = securePrefs.getDeviceId()
        )
        val rowId = sensorEventDao.insert(entity)
        Log.d(TAG, "Logged event rowId=$rowId pkg=$packageName sensor=$sensor action=$action risk=$riskScore")
    }

    /**
     * Observe the most recent [limit] events as domain models.
     * Emits a new list on every database change.
     */
    fun getRecentEvents(limit: Int = 50): Flow<List<SensorEvent>> {
        return sensorEventDao.getRecentEvents(limit).map { entities ->
            entities.map { it.toDomain() }
        }
    }

    /**
     * Observe all events as domain models.
     */
    fun getAllEvents(): Flow<List<SensorEvent>> {
        return sensorEventDao.getAllEvents().map { entities ->
            entities.map { it.toDomain() }
        }
    }

    /**
     * Returns all events that have not been synced to the server yet.
     * Called from SyncWorker on a background thread.
     */
    suspend fun getUnsyncedEvents(): List<SensorEvent> {
        return sensorEventDao.getUnsynced().map { it.toDomain() }
    }

    /**
     * Marks the given event IDs as synced.
     * Called after successful API upload.
     */
    suspend fun markSynced(ids: List<Long>) {
        if (ids.isEmpty()) return
        sensorEventDao.markSynced(ids)
        Log.d(TAG, "Marked ${ids.size} events as synced")
    }

    /**
     * Observe total event count for the dashboard counter.
     */
    fun getEventCount(): Flow<Int> = sensorEventDao.getEventCount()

    /**
     * Observe count of events pending upload to the backend.
     * Drives the unsynced badge in HomeScreen / DebugScreen.
     */
    fun getUnsyncedCount(): Flow<Int> = sensorEventDao.getUnsyncedCount()

    /**
     * Logs a Liberty Shield system/lifecycle event (not a sensor hardware access).
     *
     * Examples: service_started, boot_completed, permission_missing.
     * These appear in the event log under SensorType.SYSTEM so they are
     * visible in EventFilter.ALL but excluded from MICROPHONE / CAMERA filters.
     *
     * @param action  An EventAction constant (e.g. EventAction.SERVICE_STARTED)
     * @param label   Human-readable description (default: "Liberty Shield")
     * @param riskScore 0 for lifecycle events; non-zero for configuration warnings
     */
    suspend fun logSystemEvent(
        action:    String,
        label:     String = "Liberty Shield",
        riskScore: Int    = 0
    ) {
        logEvent(
            packageName       = LS_PACKAGE,
            appLabel          = label,
            sensor            = SensorType.SYSTEM,
            action            = action,
            riskScore         = riskScore,
            misdirectionActive = false
        )
    }
}
