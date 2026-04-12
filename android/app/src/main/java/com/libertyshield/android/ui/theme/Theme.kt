/*
 * Threat model: Theme layer.
 * No security concerns — pure presentation layer.
 *
 * IMPORTANT: Only dark theme is provided. No light theme exists.
 * Rationale: Dark theme reduces OLED power, reduces screen reflection
 * (useful in covert monitoring scenarios), and is the Liberty Shield brand.
 */
package com.libertyshield.android.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LibertyShieldColorScheme: ColorScheme = darkColorScheme(
    // Primary brand color
    primary = ShieldAccent,
    onPrimary = Color.White,
    primaryContainer = ShieldAccentDim,
    onPrimaryContainer = Color.White,

    // Secondary — used for secondary buttons / chips
    secondary = ShieldBorder,
    onSecondary = ShieldTextPrimary,
    secondaryContainer = ShieldSurface,
    onSecondaryContainer = ShieldTextPrimary,

    // Error colors
    error = ShieldRed,
    onError = Color.White,
    errorContainer = Color(0xFF7F1D1D),
    onErrorContainer = ShieldRed,

    // Background
    background = ShieldBlack,
    onBackground = ShieldTextPrimary,

    // Surface
    surface = ShieldSurface,
    onSurface = ShieldTextPrimary,
    surfaceVariant = ShieldBorder,
    onSurfaceVariant = ShieldTextMuted,
    surfaceTint = ShieldAccent,

    // Outline
    outline = ShieldBorder,
    outlineVariant = Color(0xFF0F1521),

    // Inverse (used in snackbars)
    inverseSurface = ShieldTextPrimary,
    inverseOnSurface = ShieldBlack,
    inversePrimary = ShieldAccentDim
)

/**
 * Liberty Shield Material3 theme — always dark, no dynamic color, no light variant.
 *
 * Usage:
 *   LibertyShieldTheme {
 *       // Your composables here
 *   }
 */
@Composable
fun LibertyShieldTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = LibertyShieldColorScheme,
        typography = LibertyShieldTypography,
        content = content
    )
}
