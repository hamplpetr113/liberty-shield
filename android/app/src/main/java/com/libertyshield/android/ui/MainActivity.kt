/*
 * Threat model: Application entry screen.
 * FLAG_SECURE prevents screenshots/screen recording by other apps.
 * Risk: Permission denial → graceful degradation with explanation dialogs.
 * Risk: Recents screen thumbnail leaks sensitive data → FLAG_SECURE covers Recents.
 * Risk: Accessibility service sniffing → FLAG_SECURE limits, but not fully mitigated.
 */
package com.libertyshield.android.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.libertyshield.android.ui.screens.EventsScreen
import com.libertyshield.android.ui.screens.HomeScreen
import com.libertyshield.android.ui.screens.SettingsScreen
import com.libertyshield.android.ui.theme.LibertyShieldTheme
import com.libertyshield.android.ui.theme.ShieldAccent
import com.libertyshield.android.ui.theme.ShieldBorder
import com.libertyshield.android.ui.theme.ShieldSurface
import com.libertyshield.android.ui.theme.ShieldTextMuted
import dagger.hilt.android.AndroidEntryPoint

object NavRoutes {
    const val HOME = "home"
    const val EVENTS = "events"
    const val SETTINGS = "settings"
}

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    // Permissions required for sensor monitoring
    private val requiredPermissions = buildList {
        add(Manifest.permission.RECORD_AUDIO)
        add(Manifest.permission.CAMERA)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }
    }.toTypedArray()

    private var showPermissionRationale by mutableStateOf(false)
    private var pendingPermissions by mutableStateOf<Array<String>>(emptyArray())

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val denied = results.filterValues { !it }.keys.toList()
        if (denied.isNotEmpty()) {
            android.util.Log.w("MainActivity", "Denied permissions: $denied")
            // App degrades gracefully — service still runs, but sensor detection may be limited
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        try {
            super.onCreate(savedInstanceState)

            // SECURITY: Prevent screenshots and Recents thumbnails
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

            // Request permissions — do NOT start the service here.
            // The service is only started when the user presses "Start" in HomeScreen,
            // by which point all required permissions are already confirmed.
            checkAndRequestPermissions()

            setContent {
                LibertyShieldTheme {
                    if (showPermissionRationale) {
                        PermissionRationaleDialog(
                            permissions = pendingPermissions,
                            onConfirm = {
                                showPermissionRationale = false
                                permissionLauncher.launch(pendingPermissions)
                            },
                            onDismiss = {
                                showPermissionRationale = false
                                // Request anyway — user can deny in system dialog
                                permissionLauncher.launch(pendingPermissions)
                            }
                        )
                    }
                    LibertyShieldApp()
                }
            }
        } catch (e: Throwable) {
            android.util.Log.e("LibertyShield", "CRASH in MainActivity.onCreate: ${e.message}", e)
            throw e
        }
    }

    private fun checkAndRequestPermissions() {
        val missing = requiredPermissions.filter { permission ->
            ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED
        }.toTypedArray()

        if (missing.isEmpty()) return

        // Check if we should show rationale for any missing permission
        val shouldShowRationale = missing.any { shouldShowRequestPermissionRationale(it) }

        if (shouldShowRationale) {
            pendingPermissions = missing
            showPermissionRationale = true
        } else {
            permissionLauncher.launch(missing)
        }
    }
}

@Composable
private fun LibertyShieldApp() {
    val navController = rememberNavController()

    val navItems = listOf(
        Triple(NavRoutes.HOME, "Home", Icons.Default.Home),
        Triple(NavRoutes.EVENTS, "Events", Icons.Default.List),
        Triple(NavRoutes.SETTINGS, "Settings", Icons.Default.Settings)
    )

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = ShieldSurface,
                tonalElevation = androidx.compose.ui.unit.Dp.Unspecified
            ) {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination

                navItems.forEach { (route, label, icon) ->
                    val selected = currentDestination?.hierarchy?.any { it.route == route } == true
                    NavigationBarItem(
                        icon = {
                            Icon(
                                imageVector = icon,
                                contentDescription = label
                            )
                        },
                        label = {
                            Text(
                                text = label,
                                style = MaterialTheme.typography.labelMedium
                            )
                        },
                        selected = selected,
                        onClick = {
                            navController.navigate(route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = ShieldAccent,
                            selectedTextColor = ShieldAccent,
                            unselectedIconColor = ShieldTextMuted,
                            unselectedTextColor = ShieldTextMuted,
                            indicatorColor = ShieldAccent.copy(alpha = 0.12f)
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(innerPadding)
        ) {
            NavHost(
                navController = navController,
                startDestination = NavRoutes.HOME
            ) {
                composable(NavRoutes.HOME) {
                    HomeScreen(
                        onNavigateToEvents = {
                            navController.navigate(NavRoutes.EVENTS)
                        }
                    )
                }
                composable(NavRoutes.EVENTS) {
                    EventsScreen()
                }
                composable(NavRoutes.SETTINGS) {
                    SettingsScreen()
                }
            }
        }
    }
}

@Composable
private fun PermissionRationaleDialog(
    permissions: Array<String>,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    val permissionDescriptions = permissions.mapNotNull { permission ->
        when (permission) {
            Manifest.permission.RECORD_AUDIO -> "Microphone — required to detect unauthorized microphone access by other apps"
            Manifest.permission.CAMERA -> "Camera — required to detect unauthorized camera access by other apps"
            Manifest.permission.POST_NOTIFICATIONS -> "Notifications — required to alert you when sensor access is detected"
            else -> null
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Permissions Required",
                style = MaterialTheme.typography.titleMedium,
                color = androidx.compose.ui.graphics.Color.White
            )
        },
        text = {
            Text(
                text = "Liberty Shield needs the following permissions to protect your device:\n\n" +
                    permissionDescriptions.joinToString("\n\n• ", prefix = "• "),
                style = MaterialTheme.typography.bodyMedium
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text("Grant Permissions", color = ShieldAccent)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Skip", color = ShieldTextMuted)
            }
        },
        containerColor = ShieldSurface,
        titleContentColor = androidx.compose.ui.graphics.Color.White,
        textContentColor = ShieldTextMuted
    )
}
