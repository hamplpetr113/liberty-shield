/*
 * Threat model: Domain model layer.
 * Decoupled from both Room entities and network DTOs.
 * Domain model contains no framework annotations — pure Kotlin data class.
 *
 * Risk: Serialized data contains PII (app label, package name) →
 *   toApiPayload() only sends what the server needs; no user identifiers beyond deviceId.
 */
package com.libertyshield.android.data.model

import com.libertyshield.android.data.db.SensorEventEntity
import com.libertyshield.android.engine.SensorType

data class SensorEvent(
    val id: Long = 0,
    val packageName: String,
    val appLabel: String,
    val sensor: SensorType,
    val action: String,           // "start" or "stop"
    val riskScore: Int,
    val misdirectionActive: Boolean,
    val synced: Boolean,
    val timestamp: Long,
    val deviceId: String
)

// ===== MAPPING EXTENSIONS =====

fun SensorEventEntity.toDomain(): SensorEvent = SensorEvent(
    id = id,
    packageName = packageName,
    appLabel = appLabel,
    sensor = when (sensor.lowercase()) {
        "camera" -> SensorType.CAMERA
        "system" -> SensorType.SYSTEM
        else     -> SensorType.MICROPHONE
    },
    action = action,
    riskScore = riskScore,
    misdirectionActive = misdirectionActive,
    synced = synced,
    timestamp = timestamp,
    deviceId = deviceId
)

fun SensorEvent.toEntity(): SensorEventEntity = SensorEventEntity(
    id = id,
    packageName = packageName,
    appLabel = appLabel,
    sensor = sensor.name.lowercase(),
    action = action,
    riskScore = riskScore,
    misdirectionActive = misdirectionActive,
    synced = synced,
    timestamp = timestamp,
    deviceId = deviceId
)

/**
 * Converts domain event to a flat map suitable for the API payload.
 * Field names use snake_case to match the server schema.
 */
fun SensorEvent.toApiPayload(): Map<String, Any> = mapOf(
    "device_id" to deviceId,
    "sensor" to sensor.name.lowercase(),
    "app_package" to packageName,
    "app_label" to appLabel,
    "action" to action,
    "risk_score" to riskScore,
    "misdirection_active" to misdirectionActive,
    "ts" to timestamp
)
