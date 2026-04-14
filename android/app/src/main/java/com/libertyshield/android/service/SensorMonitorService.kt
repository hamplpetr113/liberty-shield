/*
 * Threat model: Core protection layer.
 * This service runs permanently in the foreground.
 *
 * Detection method (PASSIVE):
 *   API 29+: AppOpsManager.isOperationActive() — returns true ONLY when the hardware
 *            is actively in use by that package right now. Real-time signal.
 *   API 26-28: AppOpsManager.checkOpNoThrow() — reflects permission grant state,
 *              not live hardware use. Higher false-positive rate on older devices.
 *
 * Monitoring is intentionally passive:
 *   - The service does NOT open microphone or camera hardware.
 *   - Misdirection (AudioTrack white noise / torch) is disabled by default.
 *     It caused an audible hiss when any app launched with Shield ON because
 *     checkOpNoThrow() returned MODE_ALLOWED for all apps with the permission
 *     (not just ones actively recording), creating constant false positives.
 *   - Foreground service type is DATA_SYNC — no microphone/camera privacy indicator.
 *
 * Risks:
 *   - Polling battery impact → mitigated by 2s interval + doze awareness
 *   - Missing detection window → acceptable with 2s poll
 *   - Service killed by system → START_STICKY + WorkManager 15-min heartbeat
 *   - Service killed by OEM battery saver → user guided to exclude from battery opt
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
        // Defensively stop misdirection in case it was manually activated from outside
        // this service (e.g., a future Settings toggle). Both calls are no-ops when
        // misdirection is not active — they check isMicMisdirectionActive first.
        try { misdirectionEngine.stopMicrophoneMisdirection() } catch (e: Exception) { Log.w(TAG, "Stop mic misdirection: ${e.message}") }
        try { misdirectionEngine.stopCameraMisdirection(this) } catch (e: Exception) { Log.w(TAG, "Stop cam misdirection: ${e.message}") }

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
     * Starts the foreground service in PASSIVE monitoring mode.
     *
     * Detection is via AppOpsManager.isOperationActive() — we never open the
     * microphone or camera hardware ourselves. Therefore we must NOT request
     * FOREGROUND_SERVICE_TYPE_MICROPHONE or FOREGROUND_SERVICE_TYPE_CAMERA:
     *
     *   1. Requesting those types shows the microphone/camera privacy indicator
     *      in the status bar, misleading the user into thinking we are recording.
     *   2. On some devices, requesting the audio service type causes an audio-path
     *      hardware initialisation side-effect (audible hiss/click).
     *   3. Those types are only required when the service itself opens the hardware.
     *
     * We use FOREGROUND_SERVICE_TYPE_DATA_SYNC on API 34+ (a type declaration is
     * mandatory) and the no-type overload on API 29–33. On API 26–28, any
     * startForeground() call works.
     */
    private fun startForegroundSafely(notification: Notification) {
        val hasMic = ContextCompat.checkSelfPermission(
            this, Manifest.permission.RECORD_AUDIO
        ) == PackageManager.PERMISSION_GRANTED
        val hasCam = ContextCompat.checkSelfPermission(
            this, Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED

        Log.i(TAG, "startForegroundSafely: passive/dataSync mode  hasMic=$hasMic  hasCam=$hasCam  API=${Build.VERSION.SDK_INT}")

        if (!hasMic || !hasCam) {
            Log.w(TAG, "One or more permissions missing — detection may be limited  hasMic=$hasMic  hasCam=$hasCam")
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

        try {
            if (Build.VERSION.SDK_INT >= 34) {
                // API 34 (Android 14)+: a foreground service type is mandatory.
                // DATA_SYNC is correct for a background monitoring/upload service
                // that does not open camera or microphone hardware.
                startForeground(
                    NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "startForeground failed: ${e.message}", e)
            // Last-resort fallback — try without type on any unexpected failure.
            try { startForeground(NOTIFICATION_ID, notification) }
            catch (e2: Exception) {
                Log.e(TAG, "startForeground fallback also failed: ${e2.message}")
            }
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
            // PASSIVE MONITORING ONLY — misdirection (AudioTrack white noise / torch) is
            // intentionally disabled here.
            //
            // Why: Misdirection played audio through the device speaker every time any app
            // with RECORD_AUDIO permission transitioned to background, causing an audible
            // hiss. Even with the detection API now fixed (isOperationActive instead of
            // checkOpNoThrow), auto-triggering the speaker on real detections would:
            //   1. Produce audible noise that reveals our presence to the attacker
            //   2. Drain battery (continuous AudioTrack streaming)
            //   3. Interfere with legitimate media playback
            //
            // Detection is logged and stored. Enable misdirection explicitly via Settings
            // when implementing a user-controlled opt-in toggle.
            Log.w(TAG, "HIGH RISK — passive detection only: $packageName / $sensor risk=$riskScore (misdirection disabled)")
        }

        lastDetectionTime[packageName] = now

        serviceScope.launch(Dispatchers.IO) {
            try {
                eventRepository.logEvent(
                    packageName        = packageName,
                    appLabel           = appLabel,
                    sensor             = sensor,
                    action             = EventAction.SENSOR_START,
                    riskScore          = riskScore,
                    misdirectionActive = false   // misdirection not auto-activated
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to log SENSOR_START event for $packageName: ${e.message}")
            }
        }
    }

    private fun handleSensorStop(packageName: String, sensor: SensorType) {
        Log.d(TAG, "Sensor STOP: $packageName / $sensor")

        // No misdirection to stop — misdirection auto-activation is disabled.
        // If misdirection is ever re-enabled via a user toggle, stop calls
        // belong here:
        //   misdirectionEngine.stopMicrophoneMisdirection()
        //   misdirectionEngine.stopCameraMisdirection(this)

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
