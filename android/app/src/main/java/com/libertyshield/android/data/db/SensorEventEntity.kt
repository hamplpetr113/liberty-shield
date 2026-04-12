/*
 * Threat model: Persistence layer.
 * All data encrypted at rest via SQLCipher.
 * No plaintext sensitive data in unencrypted storage.
 *
 * Risk: Column type mismatch on schema migration → version controlled, destructive fallback
 * Risk: Boolean storage as INT 0/1 in SQLite → Room handles transparently
 */
package com.libertyshield.android.data.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "sensor_events",
    indices = [
        Index(value = ["timestamp"]),
        Index(value = ["synced"]),
        Index(value = ["packageName"])
    ]
)
data class SensorEventEntity(
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "id")
    val id: Long = 0,

    @ColumnInfo(name = "packageName")
    val packageName: String,

    @ColumnInfo(name = "appLabel")
    val appLabel: String,

    /** "microphone" or "camera" */
    @ColumnInfo(name = "sensor")
    val sensor: String,

    /** "start" or "stop" */
    @ColumnInfo(name = "action")
    val action: String,

    @ColumnInfo(name = "riskScore")
    val riskScore: Int,

    @ColumnInfo(name = "misdirectionActive")
    val misdirectionActive: Boolean,

    @ColumnInfo(name = "synced", defaultValue = "0")
    val synced: Boolean = false,

    @ColumnInfo(name = "timestamp")
    val timestamp: Long,

    @ColumnInfo(name = "deviceId")
    val deviceId: String
)
