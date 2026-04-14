/*
 * Centralised constants for sensor event action strings.
 *
 * Using constants instead of raw strings:
 *   - eliminates typos across SensorMonitorService, BootReceiver, SyncWorker
 *   - makes Kotlin exhaustive-when checks possible at call sites
 *   - enables safe refactoring without grep-based search
 *
 * The constants are stored verbatim in the Room `action` column (TEXT),
 * so changing a value here is a schema migration — don't rename without bumping DB version.
 */
package com.libertyshield.android.data.model

object EventAction {

    // ── Sensor hardware access (from SensorMonitorService polling) ─────────────
    const val SENSOR_START = "start"
    const val SENSOR_STOP  = "stop"

    // ── Service lifecycle ──────────────────────────────────────────────────────
    const val SERVICE_STARTED = "service_started"
    const val SERVICE_STOPPED = "service_stopped"

    // ── User-driven shield state ───────────────────────────────────────────────
    const val SHIELD_ENABLED  = "shield_enabled"
    const val SHIELD_DISABLED = "shield_disabled"

    // ── Device events ──────────────────────────────────────────────────────────
    const val BOOT_COMPLETED = "boot_completed"

    // ── Configuration warnings (written once per session when detected) ────────
    const val PERMISSION_MISSING    = "permission_missing"
    const val BATTERY_OPT_ACTIVE    = "battery_opt_active"
    const val USAGE_ACCESS_MISSING  = "usage_access_missing"

    // ── App lifecycle ──────────────────────────────────────────────────────────
    const val APP_LAUNCH = "app_launch"

    // ── Sync outcome events ────────────────────────────────────────────────────
    const val SYNC_STARTED = "sync_started"
    const val SYNC_SUCCESS = "sync_success"
    const val SYNC_FAILED  = "sync_failed"
}

/** Human-readable label for display in the event log. */
fun String.toEventActionLabel(): String = when (this) {
    EventAction.SENSOR_START          -> "Sensor Start"
    EventAction.SENSOR_STOP           -> "Sensor Stop"
    EventAction.SERVICE_STARTED       -> "Service Started"
    EventAction.SERVICE_STOPPED       -> "Service Stopped"
    EventAction.SHIELD_ENABLED        -> "Shield Enabled"
    EventAction.SHIELD_DISABLED       -> "Shield Disabled"
    EventAction.BOOT_COMPLETED        -> "Boot Completed"
    EventAction.PERMISSION_MISSING    -> "Permission Missing"
    EventAction.BATTERY_OPT_ACTIVE    -> "Battery Opt Active"
    EventAction.USAGE_ACCESS_MISSING  -> "Usage Access Missing"
    EventAction.APP_LAUNCH             -> "App Launch"
    EventAction.SYNC_STARTED          -> "Sync Started"
    EventAction.SYNC_SUCCESS          -> "Sync Success"
    EventAction.SYNC_FAILED           -> "Sync Failed"
    else                              -> this
}
