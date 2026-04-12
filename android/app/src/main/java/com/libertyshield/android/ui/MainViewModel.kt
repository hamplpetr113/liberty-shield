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
import com.libertyshield.android.data.model.SensorEvent
import com.libertyshield.android.data.prefs.SecurePrefs
import com.libertyshield.android.data.repository.EventRepository
import com.libertyshield.android.engine.SensorType
import com.libertyshield.android.service.SensorMonitorService
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

enum class EventFilter { ALL, MICROPHONE, CAMERA, HIGH_RISK }

@HiltViewModel
class MainViewModel @Inject constructor(
    private val eventRepository: EventRepository,
    private val securePrefs: SecurePrefs
) : ViewModel() {

    companion object {
        private const val HIGH_RISK_THRESHOLD = 60
        private const val RISK_WINDOW_SIZE = 10
    }

    // ===== SHIELD STATE =====

    private val _shieldActive = MutableStateFlow(false)
    val shieldActive: StateFlow<Boolean> = _shieldActive

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

    // ===== RISK LEVEL =====

    /**
     * Risk level (0-100) computed as the maximum risk score
     * across the last [RISK_WINDOW_SIZE] events.
     */
    val riskLevel: StateFlow<Int> = recentEvents
        .map { events ->
            events
                .filter { it.action == "start" }
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
            EventFilter.ALL -> events
            EventFilter.MICROPHONE -> events.filter { it.sensor == SensorType.MICROPHONE }
            EventFilter.CAMERA -> events.filter { it.sensor == SensorType.CAMERA }
            EventFilter.HIGH_RISK -> events.filter { it.riskScore > HIGH_RISK_THRESHOLD }
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

    // ===== ACTIONS =====

    fun setFilter(filter: EventFilter) {
        _activeFilter.value = filter
    }

    fun startShield(context: Context) {
        val intent = SensorMonitorService.startIntent(context)
        ContextCompat.startForegroundService(context, intent)
        _shieldActive.value = true
    }

    fun stopShield(context: Context) {
        val intent = SensorMonitorService.stopIntent(context)
        context.startService(intent)
        _shieldActive.value = false
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
