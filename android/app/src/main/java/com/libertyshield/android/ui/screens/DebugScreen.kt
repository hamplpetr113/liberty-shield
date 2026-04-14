/*
 * Debug diagnostics screen.
 * Only shown in the Debug tab. Exposes internal state for testing and support.
 * Risk: Device ID visible on screen → acceptable; it's a non-reversible installation ID.
 * Risk: API key visible → NOT shown here; use Settings screen.
 */
package com.libertyshield.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.libertyshield.android.BuildConfig
import com.libertyshield.android.ui.MainViewModel
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

@Composable
fun DebugScreen(
    viewModel: MainViewModel = hiltViewModel()
) {
    val shieldActive      by viewModel.shieldActive.collectAsState()
    val permissionState   by viewModel.permissionState.collectAsState()
    val recentEvents      by viewModel.recentEvents.collectAsState()
    val eventCount        by viewModel.eventCount.collectAsState()
    val unsyncedCount     by viewModel.unsyncedCount.collectAsState()
    val eventsPerHour     by viewModel.eventsPerHour.collectAsState()
    val lastSyncTime      by viewModel.lastSyncTime.collectAsState()
    val lastSyncSuccess   by viewModel.lastSyncSuccess.collectAsState()
    val lastSyncCount     by viewModel.lastSyncCount.collectAsState()
    val databaseAvailable by viewModel.databaseAvailable.collectAsState()
    val startupError      by viewModel.startupError.collectAsState()

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
                    imageVector = Icons.Default.BugReport,
                    contentDescription = "Debug",
                    tint = ShieldAccent,
                    modifier = Modifier.padding(end = 10.dp)
                )
                Text(
                    text = "Debug",
                    style = MaterialTheme.typography.titleLarge,
                    color = ShieldTextPrimary
                )
            }
        }

        // ===== STARTUP DIAGNOSTICS =====
        if (!databaseAvailable || startupError != null) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = RiskHigh.copy(alpha = 0.12f)),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RiskHigh)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "Startup Diagnostics",
                            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                            color = RiskHigh
                        )
                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), color = RiskHigh.copy(alpha = 0.3f))
                        DebugRow("Database", if (databaseAvailable) "OK" else "UNAVAILABLE (in-memory fallback)",
                            valueColor = if (databaseAvailable) ShieldGreen else RiskHigh)
                        if (startupError != null) {
                            DebugRow("Error", startupError ?: "", valueColor = RiskHigh)
                        }
                        if (!databaseAvailable) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Events are not persisted. Reinstall the app or clear app data if this persists.",
                                style = MaterialTheme.typography.bodySmall,
                                color = RiskMedium
                            )
                        }
                    }
                }
            }
        }

        // ===== APP INFO =====
        item {
            DebugCard(title = "App Info") {
                DebugRow("Version", "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
                DebugRow("Package", BuildConfig.APPLICATION_ID)
                DebugRow("Build type", BuildConfig.BUILD_TYPE.uppercase())
                DebugRow("Debug build", BuildConfig.DEBUG.toString())
            }
        }

        // ===== DEVICE & CONFIG =====
        item {
            DebugCard(title = "Device & Config") {
                DebugRow("Device ID", viewModel.deviceId)
                DebugRow("API base URL", viewModel.apiBaseUrl)
                DebugRow(
                    "API key set",
                    if (viewModel.hasSensorApiKey) "YES" else "NO — sync will fail",
                    valueColor = if (viewModel.hasSensorApiKey) ShieldGreen else ShieldRed
                )
                if (!viewModel.hasSensorApiKey) {
                    androidx.compose.material3.Text(
                        text = "Set SENSOR_API_KEY in Settings → Server API Key, or in local.properties for CI builds.",
                        style = MaterialTheme.typography.bodySmall,
                        color = RiskMedium,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }

        // ===== SERVICE STATE =====
        item {
            DebugCard(title = "Service State") {
                DebugRow(
                    "Shield active",
                    shieldActive.toString(),
                    valueColor = if (shieldActive) ShieldGreen else ShieldRed
                )
                DebugRow("Total events", eventCount.toString())
                DebugRow("Unsynced events", unsyncedCount.toString(),
                    valueColor = if (unsyncedCount > 0) RiskMedium else ShieldTextPrimary)
                DebugRow("Events/hour", eventsPerHour.toString())
            }
        }

        // ===== SYNC STATE =====
        item {
            DebugCard(title = "Last Sync") {
                if (lastSyncTime == 0L) {
                    DebugRow("Status", "Never synced", valueColor = ShieldTextMuted)
                } else {
                    DebugRow(
                        "Result",
                        if (lastSyncSuccess) "SUCCESS" else "FAILED",
                        valueColor = if (lastSyncSuccess) ShieldGreen else ShieldRed
                    )
                    DebugRow("Time", formatTimestamp(lastSyncTime))
                    DebugRow("Events uploaded", lastSyncCount.toString())
                }
            }
        }

        // ===== PERMISSIONS =====
        item {
            DebugCard(title = "Permissions") {
                DebugRow(
                    "RECORD_AUDIO",
                    if (permissionState.hasRecordAudio) "GRANTED" else "DENIED",
                    valueColor = if (permissionState.hasRecordAudio) ShieldGreen else ShieldRed
                )
                DebugRow(
                    "CAMERA",
                    if (permissionState.hasCamera) "GRANTED" else "DENIED",
                    valueColor = if (permissionState.hasCamera) ShieldGreen else ShieldRed
                )
                DebugRow(
                    "POST_NOTIFICATIONS",
                    if (permissionState.hasPostNotifications) "GRANTED" else "DENIED",
                    valueColor = if (permissionState.hasPostNotifications) ShieldGreen else RiskMedium
                )
                DebugRow(
                    "USAGE_ACCESS",
                    if (permissionState.hasUsageAccess) "GRANTED" else "DENIED",
                    valueColor = if (permissionState.hasUsageAccess) ShieldGreen else RiskMedium
                )
                DebugRow(
                    "Battery opt excluded",
                    if (permissionState.isBatteryOptExcluded) "YES" else "NO",
                    valueColor = if (permissionState.isBatteryOptExcluded) ShieldGreen else RiskMedium
                )
                DebugRow(
                    "canStartShield",
                    permissionState.canStartShield.toString(),
                    valueColor = if (permissionState.canStartShield) ShieldGreen else ShieldRed
                )
                DebugRow(
                    "isFullyConfigured",
                    permissionState.isFullyConfigured.toString(),
                    valueColor = if (permissionState.isFullyConfigured) ShieldGreen else RiskMedium
                )
                DebugRow(
                    "overallStatus",
                    permissionState.overallStatus.name,
                    valueColor = when (permissionState.overallStatus.name) {
                        "ACTIVE"   -> ShieldGreen
                        "PARTIAL"  -> RiskMedium
                        else       -> ShieldRed
                    }
                )
            }
        }

        // ===== LAST 20 EVENTS =====
        item {
            Text(
                text = "Last 20 Events",
                style = MaterialTheme.typography.titleMedium,
                color = ShieldTextPrimary
            )
        }

        if (recentEvents.isEmpty()) {
            item {
                Text(
                    text = "No events recorded yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = ShieldTextMuted,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }
        } else {
            items(recentEvents.take(20)) { event ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = ShieldSurface),
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = event.appLabel,
                                style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
                                color = ShieldTextPrimary,
                                modifier = Modifier.weight(1f)
                            )
                            val riskColor = when {
                                event.riskScore >= 67 -> RiskHigh
                                event.riskScore >= 34 -> RiskMedium
                                else                  -> RiskLow
                            }
                            Text(
                                text = "risk:${event.riskScore}",
                                style = MaterialTheme.typography.labelSmall,
                                color = riskColor
                            )
                        }
                        Text(
                            text = "${event.action.uppercase()} · ${event.sensor.name} · ${formatTimestamp(event.timestamp)}",
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 10.sp),
                            color = ShieldTextMuted
                        )
                        Text(
                            text = event.packageName,
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 9.sp),
                            color = ShieldTextMuted.copy(alpha = 0.6f),
                            maxLines = 1
                        )
                        if (event.misdirectionActive) {
                            Text(
                                text = "⚡ MISDIRECTION ACTIVE",
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                                color = RiskHigh
                            )
                        }
                    }
                }
            }
        }

        item { Spacer(modifier = Modifier.height(80.dp)) }
    }
}

@Composable
private fun DebugCard(
    title: String,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldSurface),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                color = ShieldAccent
            )
            HorizontalDivider(
                modifier = Modifier.padding(vertical = 8.dp),
                color = ShieldBorder,
                thickness = 1.dp
            )
            content()
        }
    }
}

@Composable
private fun DebugRow(
    label: String,
    value: String,
    valueColor: Color = ShieldTextPrimary
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = ShieldTextMuted,
            modifier = Modifier.weight(0.45f)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Medium,
                fontSize = 11.sp
            ),
            color = valueColor,
            modifier = Modifier.weight(0.55f),
            maxLines = 2
        )
    }
}

private fun formatTimestamp(ts: Long): String =
    SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(ts))
