/*
 * Threat model: Core protection layer.
 * This service runs permanently in the foreground.
 *
 * Detection method:
 *   - Polls AppOpsManager.checkOpNoThrow() for ALL installed packages every POLL_MS
 *   - Public API — works on all supported API levels (26+)
 *   - Returns MODE_ALLOWED when the system has granted the op to that package
 *
 * Risks:
 *   - Polling battery impact → mitigated by 2s interval + doze awareness
 *   - Missing detection window → acceptable with 2s poll
 *   - Service killed by system → START_STICKY auto-restart + WorkManager 15-min heartbeat
 *   - Service killed by OEM battery saver → user guided to exclude from battery optimisation
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
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.libertyshield.android.LibertyShieldApp
import com.libertyshield.android.R
import com.libertyshield.android.data.ShieldPreferences
import com.libertyshield.android.data.model.EventAction
import com.libertyshield.android.data.prefs.SecurePrefs
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
import java.util.concurrent.TimeUnit
import javax.inject.Inject

@AndroidEntryPoint
class SensorMonitorService : Service() {

    @Inject lateinit var sensorDetector:    SensorDetector
    @Inject lateinit var misdirectionEngine: MisdirectionEngine
    @Inject lateinit var eventRepository:   EventRepository
    @Inject lateinit var appOpsManager:     AppOpsManager
    @Inject lateinit var securePrefs:       SecurePrefs

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var pollJob: Job? = null

    /** True if the user explicitly pressed Stop (vs service being killed externally). */
    private var stoppedByUser = false

    /** Tracks which (packageName + sensor) pairs are currently active, to detect edges. */
    private val activeOps = mutableSetOf<String>()           // "$packageName:$sensor"

    /** Tracks last detection time per package for repeat-within-60s scoring. */
    private val lastDetectionTime = mutableMapOf<String, Long>()

    companion object {
        private const val TAG = "SensorMonitorService"
        const val NOTIFICATION_ID = 1001
        val CHANNEL_ID get() = LibertyShieldApp.NOTIFICATION_CHANNEL_ID
        private const val POLL_MS            = 2_000L
        private const val REPEAT_WINDOW_MS   = 60_000L
        private const val RISK_THRESHOLD     = 60

        /**
         * Built-in whitelist — always skipped regardless of user settings.
         * These are known system packages that legitimately access sensors during calls.
         */
        private val SYSTEM_WHITELIST = setOf(
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

    // ===== LIFECYCLE =====

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

        // Log lifecycle event to Room
        serviceScope.launch(Dispatchers.IO) {
            try {
                eventRepository.logSystemEvent(
                    action    = EventAction.SERVICE_STARTED,
                    label     = "Liberty Shield",
                    riskScore = 0
                )
            } catch (e: Exception) {
                Log.w(TAG, "Could not log SERVICE_STARTED event: ${e.message}")
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stoppedByUser = true
            Log.i(TAG, "STOP action received — stopping service")
            stopSelf()
            return START_NOT_STICKY
        }
        if (pollJob?.isActive != true) {
            pollJob = serviceScope.launch { pollSensors() }
        }
        // Schedule periodic sync heartbeat every time we (re)start
        enqueueSyncHeartbeat()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        Log.i(TAG, "SensorMonitorService destroyed (stoppedByUser=$stoppedByUser)")
        misdirectionEngine.stopMicrophoneMisdirection()
        misdirectionEngine.stopCameraMisdirection(this)

        // Log lifecycle event synchronously on a separate scope since serviceScope is cancelled below
        val appCtx = applicationContext
        CoroutineScope(Dispatchers.IO).launch {
            try {
                eventRepository.logSystemEvent(
                    action    = EventAction.SERVICE_STOPPED,
                    label     = "Liberty Shield",
                    riskScore = 0
                )
            } catch (e: Exception) {
                Log.w(TAG, "Could not log SERVICE_STOPPED event: ${e.message}")
            }
        }

        serviceScope.cancel()
        super.onDestroy()
    }

    // ===== POLLING LOOP =====

    private suspend fun pollSensors() {
        while (serviceScope.isActive) {
            try {
                val accesses   = sensorDetector.getActiveAccesses()
                val now        = System.currentTimeMillis()
                val currentKeys = accesses.map { "${it.packageName}:${it.sensor}" }.toSet()

                // STOP edges: was active, now gone
                val stopped = activeOps - currentKeys
                for (key in stopped) {
                    val parts = key.split(":")
                    if (parts.size == 2) {
                        val sensor = runCatching { SensorType.valueOf(parts[1]) }.getOrNull() ?: continue
                        handleSensorStop(parts[0], sensor)
                    }
                }

                // START edges: newly active
                val started = currentKeys - activeOps
                for (access in accesses) {
                    val key = "${access.packageName}:${access.sensor}"
                    if (key in started) {
                        handleSensorStart(
                            access.packageName,
                            access.appLabel,
                            access.sensor,
                            access.isBackground,
                            now
                        )
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

    // ===== EVENT HANDLERS =====

    private fun handleSensorStart(
        packageName: String,
        appLabel:    String,
        sensor:      SensorType,
        isBackground: Boolean,
        now:         Long
    ) {
        // Check effective whitelist = system defaults + user's custom SecurePrefs whitelist
        val effectiveWhitelist = SYSTEM_WHITELIST + securePrefs.getWhitelist()
        if (packageName in effectiveWhitelist) {
            Log.d(TAG, "Whitelisted access: $packageName / $sensor — ignored")
            return
        }

        val riskScore = calculateRiskScore(packageName, sensor, isBackground, now)
        Log.w(TAG, "Sensor START: $packageName / $sensor / risk=$riskScore / bg=$isBackground")

        // Activate misdirection if risk exceeds threshold
        if (riskScore > RISK_THRESHOLD) {
            when (sensor) {
                SensorType.MICROPHONE -> {
                    if (!misdirectionEngine.isMicMisdirectionActive) {
                        misdirectionEngine.startMicrophoneMisdirection()
                        Log.i(TAG, "Mic misdirection ACTIVATED for $packageName")
                    }
                }
                SensorType.CAMERA -> {
                    if (!misdirectionEngine.isCamMisdirectionActive) {
                        misdirectionEngine.startCameraMisdirection(this)
                        Log.i(TAG, "Cam misdirection ACTIVATED for $packageName")
                    }
                }
                SensorType.SYSTEM -> { /* no misdirection for system events */ }
            }
        }

        lastDetectionTime[packageName] = now

        val misdirectionNowActive = when (sensor) {
            SensorType.MICROPHONE -> misdirectionEngine.isMicMisdirectionActive
            SensorType.CAMERA     -> misdirectionEngine.isCamMisdirectionActive
            SensorType.SYSTEM     -> false
        }

        serviceScope.launch(Dispatchers.IO) {
            eventRepository.logEvent(
                packageName        = packageName,
                appLabel           = appLabel,
                sensor             = sensor,
                action             = EventAction.SENSOR_START,
                riskScore          = riskScore,
                misdirectionActive = misdirectionNowActive
            )
        }
    }

    private fun handleSensorStop(packageName: String, sensor: SensorType) {
        Log.d(TAG, "Sensor STOP: $packageName / $sensor")

        // Deactivate misdirection only if no other threats remain for this sensor type
        val otherActiveForSensor = activeOps.any { key ->
            key.endsWith(":${sensor.name}") && !key.startsWith("$packageName:")
        }

        if (!otherActiveForSensor) {
            when (sensor) {
                SensorType.MICROPHONE -> misdirectionEngine.stopMicrophoneMisdirection()
                SensorType.CAMERA     -> misdirectionEngine.stopCameraMisdirection(this)
                SensorType.SYSTEM     -> { }
            }
        }

        serviceScope.launch(Dispatchers.IO) {
            val appLabel = runCatching {
                packageManager.getApplicationLabel(
                    packageManager.getApplicationInfo(packageName, 0)
                ).toString()
            }.getOrDefault(packageName)

            eventRepository.logEvent(
                packageName        = packageName,
                appLabel           = appLabel,
                sensor             = sensor,
                action             = EventAction.SENSOR_STOP,
                riskScore          = 0,
                misdirectionActive = false
            )
        }
    }

    // ===== RISK SCORING =====

    /**
     * Deterministic risk score (0–100) for a detected sensor access.
     *
     *  +40  Unknown third-party app (not a known system prefix)
     *  +30  Background access (app is not in the foreground)
     *  +20  Multi-sensor (both mic and cam active simultaneously for this package)
     *  +10  Repeat detection within 60 seconds
     */
    private fun calculateRiskScore(
        packageName:  String,
        sensor:       SensorType,
        isBackground: Boolean,
        now:          Long
    ): Int {
        var score = 0
        if (!isKnownSystemPackage(packageName)) score += 40
        if (isBackground) score += 30

        val otherSensor = if (sensor == SensorType.MICROPHONE) SensorType.CAMERA else SensorType.MICROPHONE
        if (activeOps.any { it.endsWith(":${otherSensor.name}") }) score += 20

        val lastTime = lastDetectionTime[packageName]
        if (lastTime != null && (now - lastTime) < REPEAT_WINDOW_MS) score += 10

        return score.coerceIn(0, 100)
    }

    private fun isKnownSystemPackage(packageName: String): Boolean =
        packageName.startsWith("com.android.") ||
        packageName.startsWith("com.google.android.") ||
        packageName.startsWith("android.")

    // ===== NOTIFICATION =====

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Liberty Shield Protection",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Liberty Shield is actively protecting your device"
            setShowBadge(false)
            enableVibration(false)
            enableLights(false)
        }
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .createNotificationChannel(channel)
    }

    private fun buildNotification() = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle(getString(R.string.notification_title))
        .setContentText(getString(R.string.notification_text))
        .setSmallIcon(R.drawable.ic_notification)
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

    // ===== SYNC HEARTBEAT =====

    /**
     * Enqueues the periodic sync worker.
     * Called each time the service starts so the job is always registered even
     * after a fresh install or after WorkManager's internal DB is cleared.
     * KEEP policy: if already scheduled, leaves it alone.
     */
    private fun enqueueSyncHeartbeat() {
        try {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val request = PeriodicWorkRequestBuilder<SyncWorker>(
                15, TimeUnit.MINUTES
            ).setConstraints(constraints).build()

            WorkManager.getInstance(applicationContext).enqueueUniquePeriodicWork(
                SyncWorker.WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enqueue sync heartbeat: ${e.message}")
        }
    }
}
