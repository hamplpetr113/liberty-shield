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
 *
 * Android 14 (API 34) note:
 *   startForeground() with FOREGROUND_SERVICE_TYPE_MICROPHONE / CAMERA throws SecurityException
 *   if the corresponding runtime permission is not granted at call time.
 *   startForegroundSafely() guards against this in ALL entry paths.
 */
package com.libertyshield.android.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.libertyshield.android.LibertyShieldApp
import com.libertyshield.android.R
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
        private const val POLL_MS          = 2_000L
        private const val REPEAT_WINDOW_MS = 60_000L
        private const val RISK_THRESHOLD   = 60

        /**
         * Built-in whitelist — always skipped regardless of user settings.
         * Includes both release AND debug variants of this app (applicationIdSuffix = ".debug").
         */
        private val SYSTEM_WHITELIST = setOf(
            "com.android.phone",
            "com.google.android.dialer",
            "com.libertyshield.android",
            "com.libertyshield.android.debug",   // debug APK (applicationIdSuffix)
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
        // MUST call startForeground() before returning from onCreate().
        // Use startForegroundSafely() to avoid SecurityException on Android 14.
        startForegroundSafely(notification)
        Log.i(TAG, "SensorMonitorService created — starting polling loop")

        serviceScope.launch(Dispatchers.IO) {
            try {
                eventRepository.logSystemEvent(
                    action    = EventAction.SERVICE_STARTED,
                    label     = "Liberty Shield",
                    riskScore = 0
                )
            } catch (e: Exception) {
                Log.w(TAG, "Could not log SERVICE_STARTED: ${e.message}")
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
        enqueueSyncHeartbeat()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        Log.i(TAG, "SensorMonitorService destroyed (stoppedByUser=$stoppedByUser)")
        try { misdirectionEngine.stopMicrophoneMisdirection() } catch (e: Exception) { Log.w(TAG, "Stop mic misdirection error: ${e.message}") }
        try { misdirectionEngine.stopCameraMisdirection(this) } catch (e: Exception) { Log.w(TAG, "Stop cam misdirection error: ${e.message}") }

        CoroutineScope(Dispatchers.IO).launch {
            try {
                eventRepository.logSystemEvent(
                    action    = EventAction.SERVICE_STOPPED,
                    label     = "Liberty Shield",
                    riskScore = 0
                )
            } catch (e: Exception) {
                Log.w(TAG, "Could not log SERVICE_STOPPED: ${e.message}")
            }
        }

        serviceScope.cancel()
        super.onDestroy()
    }

    // ===== FOREGROUND START (Android 14 safe) =====

    /**
     * Calls startForeground() with only the foreground service types for which
     * the corresponding runtime permissions are currently granted.
     *
     * On Android 14 (targetSdk 34), requesting a service type whose runtime permission
     * is not granted throws SecurityException. This method guards all entry paths:
     * - Direct user start from HomeScreen
     * - BootReceiver restart on reboot
     * - After Android auto-revokes unused-app permissions (90-day policy)
     */
    private fun startForegroundSafely(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val hasMic = ContextCompat.checkSelfPermission(
                this, Manifest.permission.RECORD_AUDIO
            ) == PackageManager.PERMISSION_GRANTED

            val hasCam = ContextCompat.checkSelfPermission(
                this, Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED

            var fgType = 0
            if (hasMic) fgType = fgType or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            if (hasCam) fgType = fgType or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA

            Log.d(TAG, "startForegroundSafely: hasMic=$hasMic hasCam=$hasCam fgType=$fgType")

            try {
                if (fgType != 0) {
                    startForeground(NOTIFICATION_ID, notification, fgType)
                } else {
                    // No sensor permissions yet — run as generic foreground service.
                    // Log a PERMISSION_MISSING system event for Debug screen visibility.
                    startForeground(NOTIFICATION_ID, notification)
                    Log.w(TAG, "Started without sensor service types — permissions not yet granted. Detection is limited.")
                    serviceScope.launch(Dispatchers.IO) {
                        try {
                            eventRepository.logSystemEvent(
                                action    = EventAction.PERMISSION_MISSING,
                                label     = "mic=$hasMic cam=$hasCam",
                                riskScore = 0
                            )
                        } catch (e: Exception) { /* non-fatal */ }
                    }
                }
            } catch (e: SecurityException) {
                // Belt-and-suspenders fallback — should not normally reach here since
                // we check permissions above, but handles race conditions on some OEMs.
                Log.e(TAG, "startForeground SecurityException (unexpected): ${e.message}", e)
                try {
                    startForeground(NOTIFICATION_ID, notification)
                } catch (e2: Exception) {
                    Log.e(TAG, "startForeground fallback also failed: ${e2.message}")
                }
            }
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    // ===== POLLING LOOP =====

    private suspend fun pollSensors() {
        // Establish a baseline BEFORE the first edge comparison.
        //
        // Without this, on the first poll: started = currentKeys - {} = ALL apps with
        // mic/camera permission (could be 20–30 on a typical device). This would
        // flood the database with false-positive START events on every service start.
        //
        // By pre-populating activeOps with the current state, only CHANGES from
        // this baseline produce events.
        try {
            val baseline = sensorDetector.getActiveAccesses()
            activeOps.addAll(baseline.map { "${it.packageName}:${it.sensor}" })
            Log.d(TAG, "Baseline established: ${activeOps.size} ops active at service start (no events fired)")
        } catch (e: Exception) {
            Log.w(TAG, "Could not establish baseline — first poll will generate startup events: ${e.message}")
        }

        while (serviceScope.isActive) {
            try {
                val accesses    = sensorDetector.getActiveAccesses()
                val now         = System.currentTimeMillis()
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
        packageName:  String,
        appLabel:     String,
        sensor:       SensorType,
        isBackground: Boolean,
        now:          Long
    ) {
        val effectiveWhitelist = SYSTEM_WHITELIST + securePrefs.getWhitelist()
        if (packageName in effectiveWhitelist) {
            Log.d(TAG, "Whitelisted: $packageName / $sensor — ignored")
            return
        }

        val riskScore = calculateRiskScore(packageName, sensor, isBackground, now)
        Log.w(TAG, "Sensor START: $packageName / $sensor / risk=$riskScore / bg=$isBackground")

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
                SensorType.SYSTEM -> { }
            }
        }

        lastDetectionTime[packageName] = now

        val misdirectionNowActive = when (sensor) {
            SensorType.MICROPHONE -> misdirectionEngine.isMicMisdirectionActive
            SensorType.CAMERA     -> misdirectionEngine.isCamMisdirectionActive
            SensorType.SYSTEM     -> false
        }

        serviceScope.launch(Dispatchers.IO) {
            try {
                eventRepository.logEvent(
                    packageName        = packageName,
                    appLabel           = appLabel,
                    sensor             = sensor,
                    action             = EventAction.SENSOR_START,
                    riskScore          = riskScore,
                    misdirectionActive = misdirectionNowActive
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to log SENSOR_START event for $packageName: ${e.message}")
            }
        }
    }

    private fun handleSensorStop(packageName: String, sensor: SensorType) {
        Log.d(TAG, "Sensor STOP: $packageName / $sensor")

        val otherActiveForSensor = activeOps.any { key ->
            key.endsWith(":${sensor.name}") && !key.startsWith("$packageName:")
        }

        if (!otherActiveForSensor) {
            try {
                when (sensor) {
                    SensorType.MICROPHONE -> misdirectionEngine.stopMicrophoneMisdirection()
                    SensorType.CAMERA     -> misdirectionEngine.stopCameraMisdirection(this)
                    SensorType.SYSTEM     -> { }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error stopping misdirection for $sensor: ${e.message}")
            }
        }

        serviceScope.launch(Dispatchers.IO) {
            try {
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
            } catch (e: Exception) {
                Log.e(TAG, "Failed to log SENSOR_STOP event for $packageName: ${e.message}")
            }
        }
    }

    // ===== RISK SCORING =====

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
