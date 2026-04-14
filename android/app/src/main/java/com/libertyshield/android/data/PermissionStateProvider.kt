/*
 * Runtime permission state checker.
 *
 * Checks all permissions Liberty Shield needs and returns a snapshot.
 * Stateless — call check() whenever you need a fresh snapshot (e.g., onResume).
 *
 * Permissions checked:
 *   RECORD_AUDIO        — runtime, required for mic detection (blocking)
 *   CAMERA              — runtime, required for camera detection (blocking)
 *   POST_NOTIFICATIONS  — runtime (API 33+), required for alert toasts (non-blocking)
 *   PACKAGE_USAGE_STATS — AppOps gate, required for background detection (non-blocking)
 *   Battery Optimisation — PowerManager query, affects service longevity (non-blocking)
 */
package com.libertyshield.android.data

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import androidx.core.content.ContextCompat

// ── Data model ────────────────────────────────────────────────────────────────

data class PermissionState(
    val hasPostNotifications: Boolean,
    val hasRecordAudio:        Boolean,
    val hasCamera:             Boolean,
    val hasUsageAccess:        Boolean,
    val isBatteryOptExcluded:  Boolean,
) {
    /**
     * Minimum permissions for the monitoring service to produce any events.
     * Battery optimisation and usage access affect quality, not startup.
     */
    val canStartShield: Boolean
        get() = hasRecordAudio && hasCamera

    /**
     * All recommended settings are in place.
     */
    val isFullyConfigured: Boolean
        get() = canStartShield
            && hasUsageAccess
            && isBatteryOptExcluded
            && (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || hasPostNotifications)

    val overallStatus: ProtectionStatus
        get() = when {
            isFullyConfigured                                    -> ProtectionStatus.ACTIVE
            canStartShield && (hasUsageAccess || isBatteryOptExcluded) -> ProtectionStatus.PARTIAL
            canStartShield                                       -> ProtectionStatus.PARTIAL
            else                                                 -> ProtectionStatus.INACTIVE
        }

    /** Ordered list of issues to present to the user. */
    val issues: List<PermissionIssue>
        get() = buildList {
            if (!hasRecordAudio) add(PermissionIssue.RECORD_AUDIO)
            if (!hasCamera) add(PermissionIssue.CAMERA)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !hasPostNotifications)
                add(PermissionIssue.POST_NOTIFICATIONS)
            if (!hasUsageAccess) add(PermissionIssue.USAGE_ACCESS)
            if (!isBatteryOptExcluded) add(PermissionIssue.BATTERY_OPTIMIZATION)
        }
}

enum class ProtectionStatus { ACTIVE, PARTIAL, INACTIVE }

enum class PermissionIssue(
    val label:    String,
    val detail:   String,
    val blocking: Boolean,   // if true, shield cannot start without this
) {
    RECORD_AUDIO(
        label    = "Microphone",
        detail   = "Required to detect unauthorized microphone access by other apps.",
        blocking = true,
    ),
    CAMERA(
        label    = "Camera",
        detail   = "Required to detect unauthorized camera access by other apps.",
        blocking = true,
    ),
    POST_NOTIFICATIONS(
        label    = "Notifications",
        detail   = "Required to alert you when suspicious sensor access is detected.",
        blocking = false,
    ),
    USAGE_ACCESS(
        label    = "Usage Access",
        detail   = "Improves background app detection accuracy. Grant in System Settings.",
        blocking = false,
    ),
    BATTERY_OPTIMIZATION(
        label    = "Battery Optimization",
        detail   = "Prevents Android from killing the protection service. Exclude in Settings.",
        blocking = false,
    ),
}

// ── Checker ───────────────────────────────────────────────────────────────────

object PermissionStateProvider {

    fun check(context: Context): PermissionState {
        val packageName = context.packageName

        val hasRecordAudio = ContextCompat.checkSelfPermission(
            context, Manifest.permission.RECORD_AUDIO
        ) == PackageManager.PERMISSION_GRANTED

        val hasCamera = ContextCompat.checkSelfPermission(
            context, Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED

        val hasPostNotifications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true // pre-13 notifications don't need a runtime grant
        }

        val hasUsageAccess = try {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(),
                packageName
            )
            mode == AppOpsManager.MODE_ALLOWED
        } catch (e: Exception) {
            false
        }

        val isBatteryOptExcluded = try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            pm.isIgnoringBatteryOptimizations(packageName)
        } catch (e: Exception) {
            false
        }

        return PermissionState(
            hasPostNotifications = hasPostNotifications,
            hasRecordAudio       = hasRecordAudio,
            hasCamera            = hasCamera,
            hasUsageAccess       = hasUsageAccess,
            isBatteryOptExcluded = isBatteryOptExcluded,
        )
    }
}
