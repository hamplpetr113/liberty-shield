/*
 * Threat model: UI color constants.
 * No security concerns — pure presentation layer.
 * Color choices: dark palette reduces OLED power usage and reduces screen
 * visibility to shoulder-surfers in low-light environments.
 */
package com.libertyshield.android.ui.theme

import androidx.compose.ui.graphics.Color

// ===== LIBERTY SHIELD DARK PALETTE =====

/** Primary background — near-black with a subtle blue undertone */
val ShieldBlack = Color(0xFF0A0C10)

/** Surface/card background — slightly lighter than ShieldBlack */
val ShieldSurface = Color(0xFF111520)

/** Border / divider color */
val ShieldBorder = Color(0xFF1E2535)

/** Primary accent — Liberty Shield brand blue */
val ShieldAccent = Color(0xFF2563EB)

/** Dimmed accent for pressed/secondary states */
val ShieldAccentDim = Color(0xFF1D4ED8)

/** Safe / success green */
val ShieldGreen = Color(0xFF22C55E)

/** Alert / danger red */
val ShieldRed = Color(0xFFEF4444)

/** Warning yellow */
val ShieldYellow = Color(0xFFEAB308)

/** Primary text — off-white, easy on eyes in dark mode */
val ShieldTextPrimary = Color(0xFFE2E8F0)

/** Secondary / muted text — slate-500 */
val ShieldTextMuted = Color(0xFF64748B)

// ===== ADDITIONAL SEMANTIC COLORS =====

/** Risk level: low (0-33) */
val RiskLow = ShieldGreen

/** Risk level: medium (34-66) */
val RiskMedium = ShieldYellow

/** Risk level: high (67-100) */
val RiskHigh = ShieldRed

/** Microphone icon tint */
val MicrophoneColor = Color(0xFF818CF8) // indigo-400

/** Camera icon tint */
val CameraColor = Color(0xFFFB923C) // orange-400
