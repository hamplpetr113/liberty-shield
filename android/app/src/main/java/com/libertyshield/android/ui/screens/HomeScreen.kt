/*
 * Threat model: UI layer — no sensitive data displayed in plaintext.
 * Risk: Screen capture by malicious app → Android FLAG_SECURE on window (set in MainActivity)
 * Risk: Accessibility service data harvesting → minimal text labels, no copy-to-clipboard
 * Risk: Side-channel via UI timing → risk level displayed only as color, not exact number
 */
package com.libertyshield.android.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Camera
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.libertyshield.android.data.model.SensorEvent
import com.libertyshield.android.engine.SensorType
import com.libertyshield.android.ui.MainViewModel
import com.libertyshield.android.ui.theme.CameraColor
import com.libertyshield.android.ui.theme.MicrophoneColor
import com.libertyshield.android.ui.theme.RiskHigh
import com.libertyshield.android.ui.theme.RiskLow
import com.libertyshield.android.ui.theme.RiskMedium
import com.libertyshield.android.ui.theme.ShieldAccent
import com.libertyshield.android.ui.theme.ShieldBorder
import com.libertyshield.android.ui.theme.ShieldGreen
import com.libertyshield.android.ui.theme.ShieldRed
import com.libertyshield.android.ui.theme.ShieldSurface
import com.libertyshield.android.ui.theme.ShieldTextMuted
import com.libertyshield.android.ui.theme.ShieldTextPrimary
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

@Composable
fun HomeScreen(
    onNavigateToEvents: () -> Unit,
    viewModel: MainViewModel = hiltViewModel()
) {
    val context = LocalContext.current
    val shieldActive by viewModel.shieldActive.collectAsState()
    val recentEvents by viewModel.recentEvents.collectAsState()
    val riskLevel by viewModel.riskLevel.collectAsState()
    val eventCount by viewModel.eventCount.collectAsState()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header
        item {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(vertical = 8.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Shield,
                    contentDescription = "Liberty Shield",
                    tint = ShieldAccent,
                    modifier = Modifier.size(28.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = "Liberty Shield",
                    style = MaterialTheme.typography.titleLarge,
                    color = ShieldTextPrimary
                )
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    text = "$eventCount events",
                    style = MaterialTheme.typography.labelSmall,
                    color = ShieldTextMuted
                )
            }
        }

        // Shield Status Card
        item {
            ShieldStatusCard(
                isActive = shieldActive,
                onStartClick = { viewModel.startShield(context) },
                onStopClick = { viewModel.stopShield(context) }
            )
        }

        // Risk Level Card
        item {
            RiskLevelCard(riskLevel = riskLevel)
        }

        // Recent Events
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Recent Activity",
                    style = MaterialTheme.typography.titleMedium,
                    color = ShieldTextPrimary
                )
                OutlinedButton(
                    onClick = onNavigateToEvents,
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
                ) {
                    Text(
                        text = "View All",
                        style = MaterialTheme.typography.labelMedium,
                        color = ShieldAccent
                    )
                }
            }
        }

        if (recentEvents.isEmpty()) {
            item {
                EmptyEventsPlaceholder(message = "No sensor activity detected yet.\nStart protection to begin monitoring.")
            }
        } else {
            items(recentEvents.take(10)) { event ->
                EventRow(event = event)
            }
        }

        item { Spacer(modifier = Modifier.height(80.dp)) }
    }
}

@Composable
private fun ShieldStatusCard(
    isActive: Boolean,
    onStartClick: () -> Unit,
    onStopClick: () -> Unit
) {
    val statusColor by animateColorAsState(
        targetValue = if (isActive) ShieldGreen else ShieldRed,
        animationSpec = tween(600),
        label = "statusColor"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isActive) 1.25f else 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldSurface),
        shape = RoundedCornerShape(16.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Animated pulse dot
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(48.dp)
            ) {
                // Outer ring (pulsing)
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .scale(pulseScale)
                        .clip(CircleShape)
                        .background(statusColor.copy(alpha = 0.15f))
                )
                // Inner dot (solid)
                Box(
                    modifier = Modifier
                        .size(16.dp)
                        .clip(CircleShape)
                        .background(statusColor)
                )
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (isActive) "ACTIVE" else "INACTIVE",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    ),
                    color = statusColor
                )
                Text(
                    text = if (isActive) "Monitoring all sensor access" else "Protection is stopped",
                    style = MaterialTheme.typography.bodySmall,
                    color = ShieldTextMuted
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            if (isActive) {
                OutlinedButton(
                    onClick = onStopClick,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = ShieldRed),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldRed)
                ) {
                    Text("Stop")
                }
            } else {
                Button(
                    onClick = onStartClick,
                    colors = ButtonDefaults.buttonColors(containerColor = ShieldAccent)
                ) {
                    Text("Start")
                }
            }
        }
    }
}

@Composable
private fun RiskLevelCard(riskLevel: Int) {
    val riskColor = when {
        riskLevel >= 67 -> RiskHigh
        riskLevel >= 34 -> RiskMedium
        else -> RiskLow
    }

    val riskLabel = when {
        riskLevel >= 67 -> "HIGH RISK"
        riskLevel >= 34 -> "MODERATE"
        else -> "LOW"
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldSurface),
        shape = RoundedCornerShape(16.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Threat Level",
                    style = MaterialTheme.typography.titleMedium,
                    color = ShieldTextPrimary
                )
                Text(
                    text = riskLabel,
                    style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                    color = riskColor
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            LinearProgressIndicator(
                progress = { riskLevel / 100f },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp)
                    .clip(RoundedCornerShape(4.dp)),
                color = riskColor,
                trackColor = ShieldBorder
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Based on last 10 detections",
                style = MaterialTheme.typography.bodySmall,
                color = ShieldTextMuted
            )
        }
    }
}

@Composable
private fun EventRow(event: SensorEvent) {
    val sensorIcon = if (event.sensor == SensorType.MICROPHONE) Icons.Default.Mic else Icons.Default.Camera
    val sensorColor = if (event.sensor == SensorType.MICROPHONE) MicrophoneColor else CameraColor

    val riskColor = when {
        event.riskScore >= 67 -> RiskHigh
        event.riskScore >= 34 -> RiskMedium
        else -> RiskLow
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldSurface),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = sensorIcon,
                contentDescription = event.sensor.name,
                tint = sensorColor,
                modifier = Modifier.size(22.dp)
            )

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = event.appLabel,
                    style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                    color = ShieldTextPrimary,
                    maxLines = 1
                )
                Text(
                    text = formatTimeAgo(event.timestamp),
                    style = MaterialTheme.typography.bodySmall,
                    color = ShieldTextMuted
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Action pill
            val actionBg = if (event.action == "start") Color(0xFF1A2D1A) else Color(0xFF1A1A2D)
            val actionColor = if (event.action == "start") ShieldGreen else ShieldTextMuted

            Box(
                modifier = Modifier
                    .background(actionBg, RoundedCornerShape(4.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
                Text(
                    text = event.action.uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = actionColor
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Risk badge
            if (event.riskScore > 0) {
                Box(
                    modifier = Modifier
                        .background(riskColor.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                        .border(1.dp, riskColor.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = "${event.riskScore}",
                        style = MaterialTheme.typography.labelSmall,
                        color = riskColor
                    )
                }
            }
        }
    }
}

@Composable
fun EmptyEventsPlaceholder(message: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = Icons.Default.Security,
            contentDescription = null,
            tint = ShieldTextMuted,
            modifier = Modifier.size(64.dp)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = ShieldTextMuted,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center
        )
    }
}

private fun formatTimeAgo(timestamp: Long): String {
    val diff = System.currentTimeMillis() - timestamp
    return when {
        diff < TimeUnit.MINUTES.toMillis(1) -> "just now"
        diff < TimeUnit.HOURS.toMillis(1) -> "${TimeUnit.MILLISECONDS.toMinutes(diff)}m ago"
        diff < TimeUnit.DAYS.toMillis(1) -> "${TimeUnit.MILLISECONDS.toHours(diff)}h ago"
        else -> SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(timestamp))
    }
}
