/*
 * Threat model: UI state management.
 * Risk: Stale state → StateFlow always reflects latest DB state via Room Flow.
 * Risk: Service binding complexity → simplified to direct Intent start/stop.
 * Risk: Sensitive data in ViewModel → only aggregated/display-ready data exposed.
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
        private const val HIGH_RISK_THRESHOLD = 60
        private const val RISK_WINDOW_SIZE = 10
    }

    // ===== SHIELD STATE =====

    private val _shieldActive = MutableStateFlow(ShieldPreferences.isShieldEnabled(appContext))
    val shieldActive: StateFlow<Boolean> = _shieldActive

    // ===== PERMISSION STATE =====

    private val _permissionState = MutableStateFlow(PermissionStateProvider.check(appContext))
    val permissionState: StateFlow<PermissionState> = _permissionState

    // ===== SYNC STATE =====

    private val _lastSyncTime = MutableStateFlow(ShieldPreferences.getLastSyncTime(appContext))
    val lastSyncTime: StateFlow<Long> = _lastSyncTime

    private val _lastSyncSuccess = MutableStateFlow(ShieldPreferences.getLastSyncSuccess(appContext))
    val lastSyncSuccess: StateFlow<Boolean> = _lastSyncSuccess

    private val _lastSyncCount = MutableStateFlow(ShieldPreferences.getLastSyncCount(appContext))
    val lastSyncCount: StateFlow<Int> = _lastSyncCount

    // ===== RECENT EVENTS =====

    val recentEvents: StateFlow<List<SensorEvent>> = eventRepository
        .getRecentEvents(limit = 50)
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptyList()
        )

    // ===== ALL EVENTS =====

    val allEvents: StateFlow<List<SensorEvent>> = eventRepository
        .getAllEvents()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptyList()
        )

    // ===== UNSYNCED COUNT =====

    val unsyncedCount: StateFlow<Int> = eventRepository
        .getUnsyncedCount()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = 0
        )

    // ===== EVENTS PER HOUR =====

    val eventsPerHour: StateFlow<Int> = recentEvents
        .map { events ->
            val oneHourAgo = System.currentTimeMillis() - 3_600_000L
            events.count { it.timestamp >= oneHourAgo && it.action == EventAction.SENSOR_START }
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
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
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
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
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = emptyList()
    )

    // ===== TOTAL EVENT COUNT =====

    val eventCount: StateFlow<Int> = eventRepository
        .getEventCount()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = 0
        )

    // ===== DEBUG INFO =====

    val deviceId: String get() = securePrefs.getDeviceId()
    val apiBaseUrl: String get() = BuildConfig.API_BASE_URL
    val hasSensorApiKey: Boolean get() = securePrefs.getApiKey().isNotEmpty()

    // ===== ACTIONS =====

    fun setFilter(filter: EventFilter) {
        _activeFilter.value = filter
    }

    /**
     * Re-checks permission state and shield enabled preference.
     * Call from Activity.onResume() to pick up changes made in system Settings.
     */
    fun refreshState() {
        _permissionState.value = PermissionStateProvider.check(appContext)
        _shieldActive.value = ShieldPreferences.isShieldEnabled(appContext)
        _lastSyncTime.value = ShieldPreferences.getLastSyncTime(appContext)
        _lastSyncSuccess.value = ShieldPreferences.getLastSyncSuccess(appContext)
        _lastSyncCount.value = ShieldPreferences.getLastSyncCount(appContext)
    }

    fun startShield(context: Context) {
        ShieldPreferences.setShieldEnabled(context, true)
        val intent = SensorMonitorService.startIntent(context)
        ContextCompat.startForegroundService(context, intent)
        _shieldActive.value = true

        viewModelScope.launch(Dispatchers.IO) {
            try {
                eventRepository.logSystemEvent(
                    action    = EventAction.SHIELD_ENABLED,
                    label     = "Liberty Shield",
                    riskScore = 0
                )
            } catch (e: Exception) {
                android.util.Log.w("MainViewModel", "Could not log SHIELD_ENABLED: ${e.message}")
            }
        }
    }

    fun stopShield(context: Context) {
        ShieldPreferences.setShieldEnabled(context, false)
        val intent = SensorMonitorService.stopIntent(context)
        context.startService(intent)
        _shieldActive.value = false

        viewModelScope.launch(Dispatchers.IO) {
            try {
                eventRepository.logSystemEvent(
                    action    = EventAction.SHIELD_DISABLED,
                    label     = "Liberty Shield",
                    riskScore = 0
                )
            } catch (e: Exception) {
                android.util.Log.w("MainViewModel", "Could not log SHIELD_DISABLED: ${e.message}")
            }
        }
    }

    // ===== SETTINGS HELPERS =====

    fun getApiKey(): String = securePrefs.getApiKey()

    fun setApiKey(key: String) = securePrefs.setApiKey(key)

    fun getWhitelist(): Set<String> = securePrefs.getWhitelist()

    fun addToWhitelist(packageName: String) = securePrefs.addToWhitelist(packageName)

    fun removeFromWhitelist(packageName: String) = securePrefs.removeFromWhitelist(packageName)

    fun isNotificationsEnabled(): Boolean = securePrefs.isNotificationsEnabled()

    fun setNotificationsEnabled(enabled: Boolean) = securePrefs.setNotificationsEnabled(enabled)
}
