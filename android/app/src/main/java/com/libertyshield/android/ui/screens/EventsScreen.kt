/*
 * Threat model: Events display layer.
 * Risk: Screen capture of events by malicious app → FLAG_SECURE on activity window
 * Risk: Event list contains package names — not sensitive but kept minimal
 * Risk: Copy-to-clipboard of event data → no long-press selection enabled
 */
package com.libertyshield.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Camera
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.libertyshield.android.data.model.SensorEvent
import com.libertyshield.android.engine.SensorType
import com.libertyshield.android.ui.EventFilter
import com.libertyshield.android.ui.MainViewModel
import com.libertyshield.android.ui.theme.CameraColor
import com.libertyshield.android.ui.theme.MicrophoneColor
import com.libertyshield.android.ui.theme.RiskHigh
import com.libertyshield.android.ui.theme.RiskLow
import com.libertyshield.android.ui.theme.RiskMedium
import com.libertyshield.android.ui.theme.ShieldAccent
import com.libertyshield.android.ui.theme.ShieldBorder
import com.libertyshield.android.ui.theme.ShieldGreen
import com.libertyshield.android.ui.theme.ShieldSurface
import com.libertyshield.android.ui.theme.ShieldTextMuted
import com.libertyshield.android.ui.theme.ShieldTextPrimary
import com.libertyshield.android.ui.theme.ShieldYellow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun EventsScreen(
    viewModel: MainViewModel = hiltViewModel()
) {
    val filteredEvents by viewModel.filteredEvents.collectAsState()
    val activeFilter by viewModel.activeFilter.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        // Screen title
        Text(
            text = "Event Log",
            style = MaterialTheme.typography.titleLarge,
            color = ShieldTextPrimary,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 16.dp)
        )

        // Filter bar
        LazyRow(
            contentPadding = PaddingValues(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(EventFilter.values().toList()) { filter ->
                FilterChip(
                    selected = activeFilter == filter,
                    onClick = { viewModel.setFilter(filter) },
                    label = {
                        Text(
                            text = filter.toDisplayLabel(),
                            style = MaterialTheme.typography.labelMedium
                        )
                    },
                    leadingIcon = {
                        filter.toIcon()?.let { icon ->
                            Icon(
                                imageVector = icon,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = ShieldAccent,
                        selectedLabelColor = Color.White,
                        selectedLeadingIconColor = Color.White,
                        containerColor = ShieldSurface,
                        labelColor = ShieldTextMuted
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = activeFilter == filter,
                        borderColor = ShieldBorder,
                        selectedBorderColor = ShieldAccent
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        if (filteredEvents.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                EmptyEventsPlaceholder(
                    message = when (activeFilter) {
                        EventFilter.HIGH_RISK -> "No high-risk events detected.\nYour device looks clean."
                        EventFilter.MICROPHONE -> "No microphone access events recorded."
                        EventFilter.CAMERA -> "No camera access events recorded."
                        EventFilter.ALL -> "No events recorded yet.\nStart protection to begin monitoring."
                    }
                )
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(
                    items = filteredEvents,
                    key = { event -> event.id }
                ) { event ->
                    EventDetailRow(event = event)
                }
                item { Spacer(modifier = Modifier.height(80.dp)) }
            }
        }
    }
}

@Composable
private fun EventDetailRow(event: SensorEvent) {
    val sensorIcon = if (event.sensor == SensorType.MICROPHONE) Icons.Default.Mic else Icons.Default.Camera
    val sensorColor = if (event.sensor == SensorType.MICROPHONE) MicrophoneColor else CameraColor
    val sensorLabel = if (event.sensor == SensorType.MICROPHONE) "Microphone" else "Camera"

    val riskColor = when {
        event.riskScore >= 67 -> RiskHigh
        event.riskScore >= 34 -> RiskMedium
        else -> RiskLow
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldSurface),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(
            width = if (event.riskScore >= 67) 1.dp else 1.dp,
            color = if (event.riskScore >= 67) RiskHigh.copy(alpha = 0.4f) else ShieldBorder
        )
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Top row: app info + sensor icon
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = sensorIcon,
                    contentDescription = sensorLabel,
                    tint = sensorColor,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = event.appLabel,
                        style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                        color = ShieldTextPrimary,
                        maxLines = 1
                    )
                    Text(
                        text = event.packageName,
                        style = MaterialTheme.typography.labelSmall,
                        color = ShieldTextMuted,
                        maxLines = 1
                    )
                }

                // Action pill
                val actionBg = if (event.action == "start") Color(0xFF0D2010) else Color(0xFF151520)
                val actionColor = if (event.action == "start") ShieldGreen else ShieldTextMuted

                Box(
                    modifier = Modifier
                        .background(actionBg, RoundedCornerShape(6.dp))
                        .border(1.dp, actionColor.copy(alpha = 0.3f), RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = event.action.uppercase(),
                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                        color = actionColor
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Bottom row: sensor type, risk, misdirection, timestamp
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Sensor label chip
                Box(
                    modifier = Modifier
                        .background(sensorColor.copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = sensorLabel,
                        style = MaterialTheme.typography.labelSmall,
                        color = sensorColor
                    )
                }

                Spacer(modifier = Modifier.width(6.dp))

                // Risk score badge
                if (event.riskScore > 0) {
                    Box(
                        modifier = Modifier
                            .background(riskColor.copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                            .border(1.dp, riskColor.copy(alpha = 0.35f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "Risk: ${event.riskScore}",
                            style = MaterialTheme.typography.labelSmall,
                            color = riskColor
                        )
                    }
                }

                // Misdirection indicator
                if (event.misdirectionActive) {
                    Spacer(modifier = Modifier.width(6.dp))
                    Box(
                        modifier = Modifier
                            .background(ShieldYellow.copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                            .border(1.dp, ShieldYellow.copy(alpha = 0.35f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Warning,
                                contentDescription = "Misdirection active",
                                tint = ShieldYellow,
                                modifier = Modifier.size(10.dp)
                            )
                            Spacer(modifier = Modifier.width(3.dp))
                            Text(
                                text = "MSD",
                                style = MaterialTheme.typography.labelSmall,
                                color = ShieldYellow
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.weight(1f))

                // Timestamp
                Text(
                    text = formatFullTimestamp(event.timestamp),
                    style = MaterialTheme.typography.labelSmall,
                    color = ShieldTextMuted
                )
            }
        }
    }
}

private fun EventFilter.toDisplayLabel(): String = when (this) {
    EventFilter.ALL -> "All"
    EventFilter.MICROPHONE -> "Microphone"
    EventFilter.CAMERA -> "Camera"
    EventFilter.HIGH_RISK -> "High Risk"
}

private fun EventFilter.toIcon() = when (this) {
    EventFilter.MICROPHONE -> Icons.Default.Mic
    EventFilter.CAMERA -> Icons.Default.Camera
    EventFilter.HIGH_RISK -> Icons.Default.Warning
    EventFilter.ALL -> null
}

private fun formatFullTimestamp(timestamp: Long): String {
    return SimpleDateFormat("MMM d, HH:mm:ss", Locale.getDefault()).format(Date(timestamp))
}
