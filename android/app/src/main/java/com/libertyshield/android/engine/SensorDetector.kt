/*
 * Threat model: Detection accuracy layer.
 * Wraps AppOpsManager calls with API level guards.
 *
 * Risk: False positives from system ops → whitelist + risk scoring
 * Risk: AppOpsManager API changes → version-gated implementation
 * Risk: Package enumeration performance → cached package list, refresh every 60s
 */
package com.libertyshield.android.engine

import android.app.ActivityManager
import android.app.AppOpsManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import android.util.Log
import javax.inject.Inject
import javax.inject.Singleton

enum class SensorType { MICROPHONE, CAMERA }

data class DetectedAccess(
    val packageName: String,
    val appLabel: String,
    val sensor: SensorType,
    val isBackground: Boolean,
    val timestamp: Long
)

@Singleton
class SensorDetector @Inject constructor(
    private val appOpsManager: AppOpsManager,
    private val packageManager: PackageManager,
    private val activityManager: ActivityManager
) {

    companion object {
        private const val TAG = "SensorDetector"
        private const val PACKAGE_CACHE_TTL_MS = 60_000L
        private const val ACTIVE_THRESHOLD_MS = 3000L
    }

    private var cachedPackages: List<InstalledPackage> = emptyList()
    private var cacheTimestamp: Long = 0L

    private data class InstalledPackage(
        val packageName: String,
        val uid: Int,
        val appLabel: String
    )

    /**
     * Returns all packages currently actively accessing microphone or camera.
     * Thread-safe to call from background coroutine.
     */
    fun getActiveAccesses(): List<DetectedAccess> {
        val packages = getInstalledPackages()
        val result = mutableListOf<DetectedAccess>()
        val now = System.currentTimeMillis()

        for (pkg in packages) {
            try {
                if (isOpCurrentlyActive(pkg.packageName, pkg.uid, AppOpsManager.OPSTR_RECORD_AUDIO)) {
                    result.add(
                        DetectedAccess(
                            packageName = pkg.packageName,
                            appLabel = pkg.appLabel,
                            sensor = SensorType.MICROPHONE,
                            isBackground = isBackground(pkg.packageName),
                            timestamp = now
                        )
                    )
                }
            } catch (e: Exception) {
                Log.v(TAG, "Could not check RECORD_AUDIO for ${pkg.packageName}: ${e.message}")
            }

            try {
                if (isOpCurrentlyActive(pkg.packageName, pkg.uid, AppOpsManager.OPSTR_CAMERA)) {
                    result.add(
                        DetectedAccess(
                            packageName = pkg.packageName,
                            appLabel = pkg.appLabel,
                            sensor = SensorType.CAMERA,
                            isBackground = isBackground(pkg.packageName),
                            timestamp = now
                        )
                    )
                }
            } catch (e: Exception) {
                Log.v(TAG, "Could not check CAMERA for ${pkg.packageName}: ${e.message}")
            }
        }

        return result
    }

    /**
     * Checks whether an AppOps operation is currently active for a given package.
     *
     * API 29+ (Android Q): Uses AppOpsManager.PackageOps with OpEntry.isRunning()
     *   which reflects real-time hardware access state.
     * API 26-28: Falls back to getLastAccessTime() heuristic — if the op was
     *   accessed within ACTIVE_THRESHOLD_MS, we consider it active.
     */
    @Suppress("DEPRECATION")
    private fun isOpCurrentlyActive(packageName: String, uid: Int, opStr: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val pkgOps = appOpsManager.getOpsForPackage(uid, packageName, opStr)
                pkgOps.any { pkgOp ->
                    pkgOp.ops.any { opEntry ->
                        opEntry.isRunning
                    }
                }
            } else {
                // API 26-28: check last access time heuristic
                val pkgOps = appOpsManager.getOpsForPackage(uid, packageName, opStr)
                val now = System.currentTimeMillis()
                pkgOps.any { pkgOp ->
                    pkgOp.ops.any { opEntry ->
                        val lastAccess = opEntry.lastAccessTime
                        lastAccess > 0 && (now - lastAccess) < ACTIVE_THRESHOLD_MS
                    }
                }
            }
        } catch (e: SecurityException) {
            Log.v(TAG, "SecurityException for $packageName / $opStr: ${e.message}")
            false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Returns whether the given package is currently in the background
     * (not the foreground task visible to the user).
     */
    fun isBackground(packageName: String): Boolean {
        return try {
            val runningTasks = activityManager.getRunningAppProcesses() ?: return true
            val process = runningTasks.firstOrNull { proc ->
                proc.pkgList?.contains(packageName) == true
            } ?: return true
            process.importance > ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
        } catch (e: Exception) {
            true // assume background if we can't determine
        }
    }

    private fun getUid(packageName: String): Int? {
        return try {
            packageManager.getApplicationInfo(packageName, 0).uid
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    /**
     * Returns cached list of installed packages with their UIDs and labels.
     * Cache is refreshed every PACKAGE_CACHE_TTL_MS (60 seconds).
     */
    private fun getInstalledPackages(): List<InstalledPackage> {
        val now = System.currentTimeMillis()
        if (now - cacheTimestamp < PACKAGE_CACHE_TTL_MS && cachedPackages.isNotEmpty()) {
            return cachedPackages
        }

        val installed = mutableListOf<InstalledPackage>()
        try {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                PackageManager.PackageInfoFlags.of(0L)
            } else {
                null
            }

            val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledPackages(flags!!)
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstalledPackages(0)
            }

            for (pkgInfo in packages) {
                try {
                    val uid = pkgInfo.applicationInfo?.uid ?: continue
                    val label = pkgInfo.applicationInfo?.let {
                        packageManager.getApplicationLabel(it).toString()
                    } ?: pkgInfo.packageName

                    installed.add(
                        InstalledPackage(
                            packageName = pkgInfo.packageName,
                            uid = uid,
                            appLabel = label
                        )
                    )
                } catch (e: Exception) {
                    // skip packages we can't inspect
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enumerate packages: ${e.message}")
        }

        cachedPackages = installed
        cacheTimestamp = now
        Log.d(TAG, "Package cache refreshed: ${installed.size} packages")
        return installed
    }
}
