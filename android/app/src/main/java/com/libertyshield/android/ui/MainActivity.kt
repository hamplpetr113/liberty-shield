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
import android.util.Log
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.libertyshield.android.util.CrashLogger
import com.libertyshield.android.ui.screens.DebugScreen
import com.libertyshield.android.ui.screens.EventsScreen
import com.libertyshield.android.ui.screens.HomeScreen
import com.libertyshield.android.ui.screens.SettingsScreen
import com.libertyshield.android.ui.theme.LibertyShieldTheme
import com.libertyshield.android.ui.theme.ShieldAccent
import com.libertyshield.android.ui.theme.ShieldSurface
import com.libertyshield.android.ui.theme.ShieldTextMuted
import dagger.hilt.android.AndroidEntryPoint
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object NavRoutes {
    const val HOME     = "home"
    const val EVENTS   = "events"
    const val SETTINGS = "settings"
    const val DEBUG    = "debug"
}

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    private val viewModel: MainViewModel by viewModels()

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
            Log.w(TAG, "Denied permissions: $denied")
        }
        viewModel.refreshState()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        Log.i(TAG, "MainActivity.onCreate START")
        try {
            super.onCreate(savedInstanceState)

            // SECURITY: Prevent screenshots and Recents thumbnails
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

            checkAndRequestPermissions()

            // Read any previous crash BEFORE rendering so SafeFallbackScreen can show it
            // without needing a ViewModel or DB.
            val previousCrash = CrashLogger.getLastCrash(this)
            if (previousCrash != null) {
                Log.w(TAG, "Previous crash detected: ${previousCrash.summary}")
            }

            Log.i(TAG, "setContent BEGIN")
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
                                permissionLauncher.launch(pendingPermissions)
                            }
                        )
                    }
                    if (previousCrash != null) {
                        // Show crash diagnostic screen on first launch after a crash.
                        // The user can proceed to the main app from here.
                        SafeFallbackScreen(
                            crash = previousCrash,
                            onProceed = {
                                CrashLogger.clear(this@MainActivity)
                                // Restart the activity so the normal UI loads clean
                                recreate()
                            }
                        )
                    } else {
                        LibertyShieldApp()
                    }
                }
            }
            Log.i(TAG, "setContent END")

        } catch (e: Throwable) {
            // Log but do NOT rethrow — a crash here kills the process before any UI is shown.
            Log.e(TAG, "FATAL in MainActivity.onCreate: ${e.message}", e)
            CrashLogger.saveCrash(applicationContext, e)

            // Try to render a minimal fallback. This may itself fail if super.onCreate()
            // didn't complete, but the crash is already persisted above.
            try {
                setContent {
                    SafeFallbackScreen(
                        crash = CrashLogger.getLastCrash(this@MainActivity),
                        inlineError = "${e.javaClass.simpleName}: ${e.message}",
                        onProceed = null  // Can't safely proceed if onCreate failed
                    )
                }
            } catch (fe: Throwable) {
                Log.e(TAG, "SafeFallbackScreen also failed: ${fe.message} — crash is in SharedPrefs")
            }
        }
        Log.i(TAG, "MainActivity.onCreate END")
    }

    override fun onResume() {
        super.onResume()
        // Re-check permissions in case the user granted/revoked them in system settings
        viewModel.refreshState()
    }

    private fun checkAndRequestPermissions() {
        val missing = requiredPermissions.filter { permission ->
            ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED
        }.toTypedArray()

        if (missing.isEmpty()) return

        val shouldShowRationale = missing.any { shouldShowRequestPermissionRationale(it) }

        if (shouldShowRationale) {
            pendingPermissions = missing
            showPermissionRationale = true
        } else {
            permissionLauncher.launch(missing)
        }
    }
}

// ── Ultra-safe fallback screen ────────────────────────────────────────────────
// No ViewModel, no Hilt, no Room — only plain Compose + SharedPrefs via CrashLogger.
// Renders even if the entire DI graph is broken.

@Composable
fun SafeFallbackScreen(
    crash: CrashLogger.CrashInfo?,
    inlineError: String? = null,
    onProceed: (() -> Unit)?
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0D1117))
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "Liberty Shield — Startup Failure",
            color = Color(0xFFFF4444),
            fontWeight = FontWeight.Bold,
            fontSize = 18.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "A fatal error occurred on the previous or current launch.\n" +
                   "The full stack trace is in Logcat (tag: CrashLogger / UNCAUGHT EXCEPTION).",
            color = Color(0xFFAAAAAA),
            fontSize = 13.sp
        )

        if (inlineError != null) {
            Spacer(modifier = Modifier.height(12.dp))
            CrashBlock(label = "This launch", content = inlineError)
        }

        if (crash != null) {
            Spacer(modifier = Modifier.height(12.dp))
            val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                .format(Date(crash.timestamp))
            CrashBlock(
                label   = "Last crash  ($ts  thread=${crash.threadName})",
                content = "${crash.exceptionClass}\n${crash.message}\n\n${crash.stacktrace}"
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        if (onProceed != null) {
            Button(
                onClick = onProceed,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1F6FEB))
            ) {
                Text("Clear crash log and restart", color = Color.White)
            }
        }

        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
private fun CrashBlock(label: String, content: String) {
    Text(
        text = label,
        color = Color(0xFFFF8C42),
        fontWeight = FontWeight.SemiBold,
        fontSize = 12.sp
    )
    Spacer(modifier = Modifier.height(4.dp))
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF161B22))
            .padding(10.dp)
    ) {
        Text(
            text = content,
            color = Color(0xFFE6EDF3),
            fontFamily = FontFamily.Monospace,
            fontSize = 10.sp,
            lineHeight = 15.sp
        )
    }
}

// ── Normal app shell ──────────────────────────────────────────────────────────

@Composable
private fun LibertyShieldApp() {
    // Log on every first composition of this composable (once per Activity lifecycle)
    val ctx = LocalContext.current
    SideEffect {
        Log.i("MainActivity", "LibertyShieldApp: first composition BEGIN")
    }

    val navController = rememberNavController()

    data class NavItem(val route: String, val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)

    val navItems = listOf(
        NavItem(NavRoutes.HOME,     "Home",     Icons.Default.Home),
        NavItem(NavRoutes.EVENTS,   "Events",   Icons.Default.List),
        NavItem(NavRoutes.SETTINGS, "Settings", Icons.Default.Settings),
        NavItem(NavRoutes.DEBUG,    "Debug",    Icons.Default.BugReport),
    )

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = ShieldSurface,
                tonalElevation = androidx.compose.ui.unit.Dp.Unspecified
            ) {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination

                navItems.forEach { item ->
                    val selected = currentDestination?.hierarchy?.any { it.route == item.route } == true
                    NavigationBarItem(
                        icon = {
                            Icon(
                                imageVector = item.icon,
                                contentDescription = item.label
                            )
                        },
                        label = {
                            Text(
                                text = item.label,
                                style = MaterialTheme.typography.labelMedium
                            )
                        },
                        selected = selected,
                        onClick = {
                            navController.navigate(item.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor   = ShieldAccent,
                            selectedTextColor   = ShieldAccent,
                            unselectedIconColor = ShieldTextMuted,
                            unselectedTextColor = ShieldTextMuted,
                            indicatorColor      = ShieldAccent.copy(alpha = 0.12f)
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
                composable(NavRoutes.DEBUG) {
                    DebugScreen()
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
            Manifest.permission.RECORD_AUDIO       -> "Microphone — required to detect unauthorized microphone access by other apps"
            Manifest.permission.CAMERA             -> "Camera — required to detect unauthorized camera access by other apps"
            Manifest.permission.POST_NOTIFICATIONS -> "Notifications — required to alert you when sensor access is detected"
            else                                   -> null
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
        containerColor    = ShieldSurface,
        titleContentColor = androidx.compose.ui.graphics.Color.White,
        textContentColor  = ShieldTextMuted
    )
}
