/*
 * Threat model: Typography definitions.
 * No security concerns — pure presentation layer.
 * Monospace font for data values (timestamps, risk scores, package names)
 * ensures consistent width and visual clarity for security indicators.
 */
package com.libertyshield.android.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

val LibertyShieldTypography = Typography(
    // Large title — used for screen headings
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        letterSpacing = (-0.5).sp,
        color = ShieldTextPrimary
    ),

    // Medium title — used for card headings
    titleMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.sp,
        color = ShieldTextPrimary
    ),

    // Body text — general purpose
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.5.sp,
        color = ShieldTextPrimary
    ),

    // Body medium — secondary text
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        letterSpacing = 0.25.sp,
        color = ShieldTextPrimary
    ),

    // Small body — captions, secondary info
    bodySmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.4.sp,
        color = ShieldTextMuted
    ),

    // Label small — used for data values, risk scores, timestamps
    // Monospace ensures consistent digit width for scanning security data
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.5.sp,
        color = ShieldTextMuted
    ),

    // Label medium — used for tags, badges, pills
    labelMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.5.sp,
        color = ShieldTextPrimary
    ),

    // Headline small — section headers
    headlineSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Bold,
        fontSize = 24.sp,
        lineHeight = 32.sp,
        letterSpacing = 0.sp,
        color = ShieldTextPrimary
    )
)
