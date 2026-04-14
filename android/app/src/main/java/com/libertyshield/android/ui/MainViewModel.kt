/*
 * Threat model: UI state management.
 * Risk: Stale state → StateFlow always reflects latest DB state via Room Flow.
 * Risk: Service binding complexity → simplified to direct Intent start/stop.
 * Risk: Sensitive data in ViewModel → only aggregated/display-ready data exposed.
 * Risk: DB/SecurePrefs unavailable on cold launch → all flows guarded with .catch;
 *       databaseAvailable / startupError expose degraded state to the Debug screen.
 */
package com.libertyshield.android.ui

import android.content.Context
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.libertyshield.android.BuildConfig
import com.libertyshield.android.data.PermissionState
import com.libertyshield.android.data.PermissionStateProvider
import com.libertyshield.android.data.ShieldPreferences
import com.libertyshield.android.data.model.EventAction
import com.libertyshield.android.data.model.SensorEvent
import com.libertyshield.android.data.prefs.SecurePrefs
import com.libertyshield.android.data.repository.EventRepository
import com.libertyshield.android.engine.SensorType
import com.libertyshield.android.service.SensorMonitorService
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

enum class EventFilter { ALL, MICROPHONE, CAMERA, HIGH_RISK }

@HiltViewModel
class MainViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val eventRepository: EventRepository,
    private val securePrefs: SecurePrefs
) : ViewModel() {

    companion object {
        private const val TAG = "MainViewModel"
        private const val HIGH_RISK_THRESHOLD = 60
        private const val RISK_WINDOW_SIZE = 10
    }

    // ===== STARTUP DIAGNOSTICS =====
    // Visible in DebugScreen so the user can see what failed on launch.

    init {
        Log.i(TAG, "MainViewModel INIT BEGIN")
    }

    private val _databaseAvailable = MutableStateFlow(true)
    val databaseAvailable: StateFlow<Boolean> = _databaseAvailable

    private val _startupError = MutableStateFlow<String?>(null)
    val startupError: StateFlow<String?> = _startupError

    // ===== SHIELD STATE =====

    private val _shieldActive = MutableStateFlow(
        try { ShieldPreferences.isShieldEnabled(appContext) }
        catch (e: Throwable) { android.util.Log.e(TAG, "isShieldEnabled failed: ${e.message}"); false }
    )
    val shieldActive: StateFlow<Boolean> = _shieldActive

    // ===== PERMISSION STATE =====

    private val _permissionState = MutableStateFlow(
        try { PermissionStateProvider.check(appContext) }
        catch (e: Throwable) {
            android.util.Log.e(TAG, "PermissionStateProvider.check failed: ${e.message}", e)
            PermissionState(
                hasPostNotifications = false,
                hasRecordAudio       = false,
                hasCamera            = false,
                hasUsageAccess       = false,
                isBatteryOptExcluded = false
            )
        }
    )
    val permissionState: StateFlow<PermissionState> = _permissionState

    // ===== SYNC STATE =====

    private val _lastSyncTime = MutableStateFlow(
        try { ShieldPreferences.getLastSyncTime(appContext) } catch (e: Throwable) { 0L }
    )
    val lastSyncTime: StateFlow<Long> = _lastSyncTime

    private val _lastSyncSuccess = MutableStateFlow(
        try { ShieldPreferences.getLastSyncSuccess(appContext) } catch (e: Throwable) { false }
    )
    val lastSyncSuccess: StateFlow<Boolean> = _lastSyncSuccess

    private val _lastSyncCount = MutableStateFlow(
        try { ShieldPreferences.getLastSyncCount(appContext) } catch (e: Throwable) { 0 }
    )
    val lastSyncCount: StateFlow<Int> = _lastSyncCount

    // ===== RECENT EVENTS =====

    val recentEvents: StateFlow<List<SensorEvent>> = eventRepository
        .getRecentEvents(limit = 50)
        .catch { e ->
            android.util.Log.e(TAG, "recentEvents flow error: ${e.message}", e)
            _databaseAvailable.value = false
            _startupError.value = "DB error: ${e.javaClass.simpleName}"
            emit(emptyList())
        }
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptyList()
        )

    // ===== ALL EVENTS =====

    val allEvents: StateFlow<List<SensorEvent>> = eventRepository
        .getAllEvents()
        .catch { e ->
            android.util.Log.e(TAG, "allEvents flow error: ${e.message}", e)
            _databaseAvailable.value = false
            emit(emptyList())
        }
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptyList()
        )

    // ===== UNSYNCED COUNT =====

    val unsyncedCount: StateFlow<Int> = eventRepository
        .getUnsyncedCount()
        .catch { e ->
            android.util.Log.e(TAG, "unsyncedCount flow error: ${e.message}", e)
            emit(0)
        }
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = 0
        )

    // ===== EVENTS PER HOUR =====

    val eventsPerHour: StateFlow<Int> = recentEvents
        .map { events ->
            val oneHourAgo = System.currentTimeMillis() - 3_600_000L
            events.count { it.timestamp >= oneHourAgo && it.action == EventAction.SENSOR_START }
        }
        .catch { emit(0) }
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = 0
        )

    // ===== RISK LEVEL =====

    val riskLevel: StateFlow<Int> = recentEvents
        .map { events ->
            events
                .filter { it.action == EventAction.SENSOR_START }
                .take(RISK_WINDOW_SIZE)
                .maxOfOrNull { it.riskScore } ?: 0
        }
        .catch { emit(0) }
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = 0
        )

    // ===== ACTIVE FILTER =====

    private val _activeFilter = MutableStateFlow(EventFilter.ALL)
    val activeFilter: StateFlow<EventFilter> = _activeFilter

    // ===== FILTERED EVENTS =====

    val filteredEvents: StateFlow<List<SensorEvent>> = combine(
        allEvents,
        _activeFilter
    ) { events, filter ->
        when (filter) {
            EventFilter.ALL        -> events
            EventFilter.MICROPHONE -> events.filter { it.sensor == SensorType.MICROPHONE }
            EventFilter.CAMERA     -> events.filter { it.sensor == SensorType.CAMERA }
            EventFilter.HIGH_RISK  -> events.filter { it.riskScore > HIGH_RISK_THRESHOLD }
        }
    }
        .catch { emit(emptyList()) }
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptyList()
        )

    // ===== TOTAL EVENT COUNT =====

    val eventCount: StateFlow<Int> = eventRepository
        .getEventCount()
        .catch { e ->
            android.util.Log.e(TAG, "eventCount flow error: ${e.message}", e)
            emit(0)
        }
        .stateIn(
            scope        = viewModelScope,
            started      = SharingStarted.WhileSubscribed(5_000),
            initialValue = 0
        )

    // ===== DEBUG INFO =====
    // Property getters access SecurePrefs (EncryptedSharedPreferences) which can throw.
    // Guard each one so DebugScreen renders even when crypto storage is broken.

    val deviceId: String
        get() = try { securePrefs.getDeviceId() } catch (e: Throwable) { "unavailable" }

    val apiBaseUrl: String
        get() = BuildConfig.API_BASE_URL

    val hasSensorApiKey: Boolean
        get() = try { securePrefs.getApiKey().isNotEmpty() } catch (e: Throwable) { false }

    init {
        Log.i(TAG, "MainViewModel INIT END — databaseAvailable=${_databaseAvailable.value} startupError=${_startupError.value}")
    }

    // ===== ACTIONS =====

    fun setFilter(filter: EventFilter) {
        _activeFilter.value = filter
    }

    /**
     * Re-checks permission state and shield enabled preference.
     * Call from Activity.onResume() to pick up changes made in system Settings.
     */
    fun refreshState() {
        try { _permissionState.value = PermissionStateProvider.check(appContext) }
        catch (e: Throwable) { android.util.Log.e(TAG, "refreshState permission check failed: ${e.message}") }

        try { _shieldActive.value = ShieldPreferences.isShieldEnabled(appContext) }
        catch (e: Throwable) { android.util.Log.e(TAG, "refreshState shield check failed: ${e.message}") }

        try {
            _lastSyncTime.value    = ShieldPreferences.getLastSyncTime(appContext)
            _lastSyncSuccess.value = ShieldPreferences.getLastSyncSuccess(appContext)
            _lastSyncCount.value   = ShieldPreferences.getLastSyncCount(appContext)
        } catch (e: Throwable) {
            android.util.Log.e(TAG, "refreshState sync prefs failed: ${e.message}")
        }
    }

    fun startShield(context: Context) {
        try { ShieldPreferences.setShieldEnabled(context, true) }
        catch (e: Throwable) { android.util.Log.e(TAG, "setShieldEnabled failed: ${e.message}") }

        try {
            val intent = SensorMonitorService.startIntent(context)
            ContextCompat.startForegroundService(context, intent)
        } catch (e: Throwable) {
            android.util.Log.e(TAG, "startForegroundService failed: ${e.message}", e)
        }

        _shieldActive.value = true

        viewModelScope.launch(Dispatchers.IO) {
            try {
                eventRepository.logSystemEvent(
                    action    = EventAction.SHIELD_ENABLED,
                    label     = "Liberty Shield",
                    riskScore = 0
                )
            } catch (e: Exception) {
                android.util.Log.w(TAG, "Could not log SHIELD_ENABLED: ${e.message}")
            }
        }
    }

    fun stopShield(context: Context) {
        try { ShieldPreferences.setShieldEnabled(context, false) }
        catch (e: Throwable) { android.util.Log.e(TAG, "setShieldEnabled(false) failed: ${e.message}") }

        try {
            val intent = SensorMonitorService.stopIntent(context)
            context.startService(intent)
        } catch (e: Throwable) {
            android.util.Log.e(TAG, "stopService failed: ${e.message}", e)
        }

        _shieldActive.value = false

        viewModelScope.launch(Dispatchers.IO) {
            try {
                eventRepository.logSystemEvent(
                    action    = EventAction.SHIELD_DISABLED,
                    label     = "Liberty Shield",
                    riskScore = 0
                )
            } catch (e: Exception) {
                android.util.Log.w(TAG, "Could not log SHIELD_DISABLED: ${e.message}")
            }
        }
    }

    // ===== SETTINGS HELPERS =====

    fun getApiKey(): String = try { securePrefs.getApiKey() } catch (e: Throwable) { "" }

    fun setApiKey(key: String) {
        try { securePrefs.setApiKey(key) }
        catch (e: Throwable) { android.util.Log.e(TAG, "setApiKey failed: ${e.message}") }
    }

    fun getWhitelist(): Set<String> = try { securePrefs.getWhitelist() } catch (e: Throwable) { emptySet() }

    fun addToWhitelist(packageName: String) {
        try { securePrefs.addToWhitelist(packageName) }
        catch (e: Throwable) { android.util.Log.e(TAG, "addToWhitelist failed: ${e.message}") }
    }

    fun removeFromWhitelist(packageName: String) {
        try { securePrefs.removeFromWhitelist(packageName) }
        catch (e: Throwable) { android.util.Log.e(TAG, "removeFromWhitelist failed: ${e.message}") }
    }

    fun isNotificationsEnabled(): Boolean =
        try { securePrefs.isNotificationsEnabled() } catch (e: Throwable) { true }

    fun setNotificationsEnabled(enabled: Boolean) {
        try { securePrefs.setNotificationsEnabled(enabled) }
        catch (e: Throwable) { android.util.Log.e(TAG, "setNotificationsEnabled failed: ${e.message}") }
    }
}
