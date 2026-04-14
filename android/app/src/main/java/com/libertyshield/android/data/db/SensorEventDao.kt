/*
 * Threat model: Data access layer.
 * DAO provides the only access path to the encrypted database.
 * Risk: SQL injection — prevented by Room's parameterized queries.
 * Risk: Thread violations — Room enforces background-thread queries via Dispatchers.IO.
 */
package com.libertyshield.android.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface SensorEventDao {

    /**
     * Insert a single sensor event. Returns the rowId of the inserted record.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(event: SensorEventEntity): Long

    /**
     * Observe all sensor events ordered by timestamp descending.
     * Emits a new list whenever the table changes.
     */
    @Query("SELECT * FROM sensor_events ORDER BY timestamp DESC")
    fun getAllEvents(): Flow<List<SensorEventEntity>>

    /**
     * Observe the most recent [limit] events ordered by timestamp descending.
     */
    @Query("SELECT * FROM sensor_events ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentEvents(limit: Int): Flow<List<SensorEventEntity>>

    /**
     * Synchronous query for unsynced events — called from SyncWorker background thread.
     */
    @Query("SELECT * FROM sensor_events WHERE synced = 0 ORDER BY timestamp ASC")
    suspend fun getUnsynced(): List<SensorEventEntity>

    /**
     * Mark a batch of events as synced by their IDs.
     */
    @Query("UPDATE sensor_events SET synced = 1 WHERE id IN (:ids)")
    suspend fun markSynced(ids: List<Long>)

    /**
     * Observe total event count for dashboard display.
     */
    @Query("SELECT COUNT(*) FROM sensor_events")
    fun getEventCount(): Flow<Int>

    /**
     * Observe the count of events that have not yet been synced to the backend.
     * Drives the "unsynced" badge in HomeScreen and DebugScreen.
     */
    @Query("SELECT COUNT(*) FROM sensor_events WHERE synced = 0")
    fun getUnsyncedCount(): Flow<Int>

    /**
     * Delete all events older than the given timestamp (housekeeping).
     */
    @Query("DELETE FROM sensor_events WHERE timestamp < :cutoffMs")
    suspend fun deleteOlderThan(cutoffMs: Long)
}
