/*
 * Threat model: Settings UI layer.
 * Risk: API key visible on screen → masked by default, toggle to reveal
 * Risk: API key accessible from Recents thumbnail → FLAG_SECURE on window
 * Risk: Accessibility service reading API key → masked text not selectable
 * Risk: Whitelist bypass by user → whitelist is user's choice, not a security guarantee
 */
package com.libertyshield.android.ui.screens

import android.content.Intent
import android.provider.Settings
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.libertyshield.android.BuildConfig
import com.libertyshield.android.ui.MainViewModel
import com.libertyshield.android.ui.theme.ShieldAccent
import com.libertyshield.android.ui.theme.ShieldBorder
import com.libertyshield.android.ui.theme.ShieldGreen
import com.libertyshield.android.ui.theme.ShieldRed
import com.libertyshield.android.ui.theme.ShieldSurface
import com.libertyshield.android.ui.theme.ShieldTextMuted
import com.libertyshield.android.ui.theme.ShieldTextPrimary

@Composable
fun SettingsScreen(
    viewModel: MainViewModel = hiltViewModel()
) {
    val context = LocalContext.current

    var apiKey by rememberSaveable { mutableStateOf(viewModel.getApiKey()) }
    var apiKeyVisible by rememberSaveable { mutableStateOf(false) }
    var notificationsEnabled by rememberSaveable { mutableStateOf(viewModel.isNotificationsEnabled()) }
    var whitelist by remember { mutableStateOf(viewModel.getWhitelist()) }
    var newWhitelistEntry by rememberSaveable { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Title
        item {
            Text(
                text = "Settings",
                style = MaterialTheme.typography.titleLarge,
                color = ShieldTextPrimary,
                modifier = Modifier.padding(vertical = 4.dp)
            )
        }

        // ===== API KEY =====
        item {
            SettingsCard(title = "Server API Key") {
                OutlinedTextField(
                    value = apiKey,
                    onValueChange = {
                        apiKey = it
                        viewModel.setApiKey(it)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("API Key", color = ShieldTextMuted) },
                    placeholder = { Text("Enter your Liberty Shield API key", color = ShieldTextMuted) },
                    visualTransformation = if (apiKeyVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        IconButton(onClick = { apiKeyVisible = !apiKeyVisible }) {
                            Icon(
                                imageVector = if (apiKeyVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = if (apiKeyVisible) "Hide key" else "Show key",
                                tint = ShieldTextMuted
                            )
                        }
                    },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = ShieldAccent,
                        unfocusedBorderColor = ShieldBorder,
                        focusedTextColor = ShieldTextPrimary,
                        unfocusedTextColor = ShieldTextPrimary,
                        cursorColor = ShieldAccent
                    )
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Stored encrypted on device via Android Keystore.",
                    style = MaterialTheme.typography.bodySmall,
                    color = ShieldTextMuted
                )
            }
        }

        // ===== NOTIFICATIONS =====
        item {
            SettingsCard(title = "Notifications") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Alert notifications",
                            style = MaterialTheme.typography.bodyMedium,
                            color = ShieldTextPrimary
                        )
                        Text(
                            text = "Notify on high-risk sensor access",
                            style = MaterialTheme.typography.bodySmall,
                            color = ShieldTextMuted
                        )
                    }
                    Switch(
                        checked = notificationsEnabled,
                        onCheckedChange = {
                            notificationsEnabled = it
                            viewModel.setNotificationsEnabled(it)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = ShieldGreen,
                            checkedTrackColor = ShieldGreen.copy(alpha = 0.3f),
                            uncheckedThumbColor = ShieldTextMuted,
                            uncheckedTrackColor = ShieldBorder
                        )
                    )
                }
            }
        }

        // ===== WHITELIST =====
        item {
            SettingsCard(title = "App Whitelist") {
                Text(
                    text = "Whitelisted apps will not trigger alerts when accessing sensors.",
                    style = MaterialTheme.typography.bodySmall,
                    color = ShieldTextMuted
                )
                Spacer(modifier = Modifier.height(12.dp))

                // Add new entry
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = newWhitelistEntry,
                        onValueChange = { newWhitelistEntry = it },
                        modifier = Modifier.weight(1f),
                        label = { Text("Package name", color = ShieldTextMuted) },
                        placeholder = { Text("com.example.app", color = ShieldTextMuted) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = ShieldAccent,
                            unfocusedBorderColor = ShieldBorder,
                            focusedTextColor = ShieldTextPrimary,
                            unfocusedTextColor = ShieldTextPrimary,
                            cursorColor = ShieldAccent
                        )
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    IconButton(
                        onClick = {
                            val trimmed = newWhitelistEntry.trim()
                            if (trimmed.isNotEmpty()) {
                                viewModel.addToWhitelist(trimmed)
                                whitelist = viewModel.getWhitelist()
                                newWhitelistEntry = ""
                            }
                        }
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = "Add to whitelist",
                            tint = ShieldAccent,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                // Whitelist entries
                whitelist.sorted().forEach { pkg ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(
                                MaterialTheme.colorScheme.background,
                                RoundedCornerShape(8.dp)
                            )
                            .border(1.dp, ShieldBorder, RoundedCornerShape(8.dp))
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = pkg,
                            style = MaterialTheme.typography.labelSmall,
                            color = ShieldTextPrimary,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(
                            onClick = {
                                viewModel.removeFromWhitelist(pkg)
                                whitelist = viewModel.getWhitelist()
                            },
                            modifier = Modifier.size(32.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Delete,
                                contentDescription = "Remove $pkg",
                                tint = ShieldRed,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                }
            }
        }

        // ===== BATTERY OPTIMIZATION =====
        item {
            SettingsCard(title = "Battery Optimization") {
                Text(
                    text = "For reliable monitoring, Liberty Shield needs to be excluded from battery optimization.",
                    style = MaterialTheme.typography.bodySmall,
                    color = ShieldTextMuted
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = {
                        context.startActivity(
                            Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                        )
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = ShieldSurface),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Open Battery Settings",
                        color = ShieldAccent
                    )
                }
            }
        }

        // ===== USAGE ACCESS =====
        item {
            SettingsCard(title = "Usage Access Permission") {
                Text(
                    text = "Usage access is required for accurate background app detection.",
                    style = MaterialTheme.typography.bodySmall,
                    color = ShieldTextMuted
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = {
                        context.startActivity(
                            Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                        )
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = ShieldSurface),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Request Usage Access",
                        color = ShieldAccent
                    )
                }
            }
        }

        // ===== APP VERSION =====
        item {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "Liberty Shield",
                        style = MaterialTheme.typography.bodySmall,
                        color = ShieldTextMuted
                    )
                    Text(
                        text = "v${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
                        style = MaterialTheme.typography.labelSmall,
                        color = ShieldTextMuted
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = if (BuildConfig.DEBUG) "DEBUG BUILD" else "RELEASE",
                        style = MaterialTheme.typography.labelSmall,
                        color = if (BuildConfig.DEBUG) ShieldRed else ShieldTextMuted
                    )
                }
            }
        }

        item { Spacer(modifier = Modifier.height(80.dp)) }
    }
}

@Composable
private fun SettingsCard(
    title: String,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldSurface),
        shape = RoundedCornerShape(16.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = ShieldTextPrimary
            )
            HorizontalDivider(
                modifier = Modifier.padding(vertical = 10.dp),
                color = ShieldBorder,
                thickness = 1.dp
            )
            content()
        }
    }
}
