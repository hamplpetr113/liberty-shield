/*
 * Threat model: Core protection layer.
 * This service runs permanently in the foreground.
 *
 * Detection method:
 *   - Polls AppOpsManager.getOpsForPackage() for ALL installed packages every POLL_MS
 *   - API 29+: OpEntry.isRunning() for accurate active detection
 *   - API 26-28: OpEntry.getLastAccessTime() within ACTIVE_THRESHOLD_MS
 *
 * Risks:
 *   - Polling battery impact → mitigated by 2s interval + doze awareness
 *   - Missing detection window → acceptable with 2s poll
 *   - Service killed → WorkManager restarts within 15 minutes
 */
package com.libertyshield.android.service

import android.app.AppOpsManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.libertyshield.android.BuildConfig
import com.libertyshield.android.R
import com.libertyshield.android.data.repository.EventRepository
import com.libertyshield.android.engine.MisdirectionEngine
import com.libertyshield.android.engine.SensorDetector
import com.libertyshield.android.engine.SensorType
import com.libertyshield.android.network.SyncWorker
import com.libertyshield.android.ui.MainActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class SensorMonitorService : Service() {

    @Inject lateinit var sensorDetector: SensorDetector
    @Inject lateinit var misdirectionEngine: MisdirectionEngine
    @Inject lateinit var eventRepository: EventRepository
    @Inject lateinit var appOpsManager: AppOpsManager
    // Note: packageManager is inherited from Context — no injection needed

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var pollJob: Job? = null

    /** Tracks which (packageName + sensor) pairs are currently active, to detect edges. */
    private val activeOps = mutableSetOf<String>() // key = "$packageName:$sensor"

    /** Tracks last detection time per package for repeat-within-60s scoring. */
    private val lastDetectionTime = mutableMapOf<String, Long>()

    companion object {
        private const val TAG = "SensorMonitorService"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "liberty_shield_monitor"
        private const val POLL_MS = 2000L
        private const val ACTIVE_THRESHOLD_MS = 3000L
        private const val REPEAT_WINDOW_MS = 60_000L
        private const val RISK_THRESHOLD = 60

        /** Packages that are legitimately expected to access mic/camera. */
        val WHITELIST = setOf(
            "com.android.phone",
            "com.google.android.dialer",
            "com.libertyshield.android",
            "com.android.server.telecom",
            "com.samsung.android.incallui",
            "com.google.android.googlequicksearchbox",
            "com.android.systemui"
        )

        fun startIntent(context: Context): Intent =
            Intent(context, SensorMonitorService::class.java)

        fun stopIntent(context: Context): Intent =
            Intent(context, SensorMonitorService::class.java).also {
                it.action = "STOP"
            }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE or
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        Log.i(TAG, "SensorMonitorService created — starting polling loop")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopSelf()
            return START_NOT_STICKY
        }
        if (pollJob?.isActive != true) {
            pollJob = serviceScope.launch { pollSensors() }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        Log.i(TAG, "SensorMonitorService destroyed — scheduling WorkManager restart")
        misdirectionEngine.stopMicrophoneMisdirection()
        misdirectionEngine.stopCameraMisdirection(this)
        serviceScope.cancel()
        scheduleWorkManagerRestart()
        super.onDestroy()
    }

    // ===== POLLING LOOP =====

    private suspend fun pollSensors() {
        while (serviceScope.isActive) {
            try {
                val accesses = sensorDetector.getActiveAccesses()
                val now = System.currentTimeMillis()

                val currentKeys = accesses.map { "${it.packageName}:${it.sensor}" }.toSet()

                // Detect STOP edges (was active, now gone)
                val stopped = activeOps - currentKeys
                for (key in stopped) {
                    val parts = key.split(":")
                    if (parts.size == 2) {
                        val (pkg, sensorStr) = parts
                        val sensor = runCatching { SensorType.valueOf(sensorStr) }.getOrNull() ?: continue
                        handleSensorStop(pkg, sensor)
                    }
                }

                // Detect START edges (new active ops)
                val started = currentKeys - activeOps
                for (access in accesses) {
                    val key = "${access.packageName}:${access.sensor}"
                    if (key in started) {
                        handleSensorStart(access.packageName, access.appLabel, access.sensor, access.isBackground, now)
                    }
                }

                activeOps.clear()
                activeOps.addAll(currentKeys)

            } catch (e: Exception) {
                Log.e(TAG, "Poll error: ${e.message}", e)
            }
            delay(POLL_MS)
        }
    }

    private fun handleSensorStart(
        packageName: String,
        appLabel: String,
        sensor: SensorType,
        isBackground: Boolean,
        now: Long
    ) {
        if (packageName in WHITELIST) {
            Log.d(TAG, "Whitelisted access: $packageName / $sensor — ignored")
            return
        }

        val riskScore = calculateRiskScore(packageName, sensor, isBackground, now)
        Log.w(TAG, "Sensor START detected: $packageName / $sensor / risk=$riskScore / bg=$isBackground")

        // Apply misdirection if risk is high enough
        if (riskScore > RISK_THRESHOLD) {
            when (sensor) {
                SensorType.MICROPHONE -> {
                    if (!misdirectionEngine.isMicMisdirectionActive) {
                        misdirectionEngine.startMicrophoneMisdirection()
                        Log.i(TAG, "Microphone misdirection ACTIVATED for $packageName")
                    }
                }
                SensorType.CAMERA -> {
                    if (!misdirectionEngine.isCamMisdirectionActive) {
                        misdirectionEngine.startCameraMisdirection(this)
                        Log.i(TAG, "Camera misdirection ACTIVATED for $packageName")
                    }
                }
            }
        }

        lastDetectionTime[packageName] = now

        serviceScope.launch(Dispatchers.IO) {
            eventRepository.logEvent(
                packageName = packageName,
                appLabel = appLabel,
                sensor = sensor,
                action = "start",
                riskScore = riskScore,
                misdirectionActive = when (sensor) {
                    SensorType.MICROPHONE -> misdirectionEngine.isMicMisdirectionActive
                    SensorType.CAMERA -> misdirectionEngine.isCamMisdirectionActive
                }
            )
        }
    }

    private fun handleSensorStop(packageName: String, sensor: SensorType) {
        Log.d(TAG, "Sensor STOP detected: $packageName / $sensor")

        // Only deactivate misdirection if no other active threats remain for this sensor type
        val otherActiveForSensor = activeOps.any { key ->
            key.endsWith(":${sensor.name}") && !key.startsWith("$packageName:")
        }

        if (!otherActiveForSensor) {
            when (sensor) {
                SensorType.MICROPHONE -> misdirectionEngine.stopMicrophoneMisdirection()
                SensorType.CAMERA -> misdirectionEngine.stopCameraMisdirection(this)
            }
        }

        serviceScope.launch(Dispatchers.IO) {
            val appLabel = runCatching {
                packageManager.getApplicationLabel(
                    packageManager.getApplicationInfo(packageName, 0)
                ).toString()
            }.getOrDefault(packageName)

            eventRepository.logEvent(
                packageName = packageName,
                appLabel = appLabel,
                sensor = sensor,
                action = "stop",
                riskScore = 0,
                misdirectionActive = false
            )
        }
    }

    // ===== RISK SCORING =====

    /**
     * Calculate a risk score 0-100 for a detected sensor access.
     *
     * Factors:
     *   +40  Unknown app (not in whitelist — already filtered, but for scoring)
     *   +30  Background access (app not in foreground)
     *   +20  Multi-sensor (both mic and cam active simultaneously)
     *   +10  Repeat detection within 60 seconds
     */
    private fun calculateRiskScore(
        packageName: String,
        sensor: SensorType,
        isBackground: Boolean,
        now: Long
    ): Int {
        var score = 0

        // Unknown app (not a known system package)
        val isKnownSystem = isKnownSystemPackage(packageName)
        if (!isKnownSystem) score += 40

        // Background access
        if (isBackground) score += 30

        // Multi-sensor: check if the other sensor type is also active
        val otherSensor = if (sensor == SensorType.MICROPHONE) SensorType.CAMERA else SensorType.MICROPHONE
        val otherActive = activeOps.any { it.endsWith(":${otherSensor.name}") }
        if (otherActive) score += 20

        // Repeat within 60s
        val lastTime = lastDetectionTime[packageName]
        if (lastTime != null && (now - lastTime) < REPEAT_WINDOW_MS) score += 10

        return score.coerceIn(0, 100)
    }

    private fun isKnownSystemPackage(packageName: String): Boolean {
        return packageName.startsWith("com.android.") ||
               packageName.startsWith("com.google.android.") ||
               packageName.startsWith("android.")
    }

    // ===== NOTIFICATION =====

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_desc)
            setShowBadge(false)
            enableVibration(false)
            enableLights(false)
        }
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification() = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle(getString(R.string.notification_title))
        .setContentText(getString(R.string.notification_text))
        .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
        .setOngoing(true)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setContentIntent(
            PendingIntent.getActivity(
                this, 0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        .build()

    // ===== WORKMANAGER RESTART =====

    private fun scheduleWorkManagerRestart() {
        try {
            val request = OneTimeWorkRequestBuilder<SyncWorker>().build()
            WorkManager.getInstance(applicationContext).enqueue(request)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to schedule WorkManager restart: ${e.message}")
        }
    }
}
