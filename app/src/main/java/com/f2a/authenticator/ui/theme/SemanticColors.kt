package com.f2a.authenticator.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * 深浅色自适应语义色表（保证深浅模式下全部文字、计时器与环境角标对比度 >= 4.5:1）。
 */
@Immutable
data class SemanticColors(
    val isDark: Boolean,
    val timerNormal: Color,
    val timerWarning: Color,
    val timerDanger: Color,
    val success: Color,
    val onSuccess: Color,
    val warningBg: Color,
    val warningText: Color,
    val errorText: Color,
    val borderSubtle: Color,
    val surfaceElevated: Color,
    val scrim: Color,
    val envProdBg: Color,
    val envProdText: Color,
    val envDevBg: Color,
    val envDevText: Color,
    val envStageBg: Color,
    val envStageText: Color,
    val envOtherBg: Color,
    val envOtherText: Color
)

val DarkSemanticColors = SemanticColors(
    isDark = true,
    timerNormal = Color(0xFF5A9BFF),
    timerWarning = Color(0xFFFBBF24),
    timerDanger = Color(0xFFF87171),
    success = Color(0xFF34D399),
    onSuccess = Color(0xFF05261A),
    warningBg = Color(0xFF2B2212),
    warningText = Color(0xFFFCD34D),
    errorText = Color(0xFFFCA5A5),
    borderSubtle = Color(0x1AFFFFFF),
    surfaceElevated = NavySurfaceContainerHigh,
    scrim = Color(0x99050912),
    envProdBg = Color(0xFF2E1A22),
    envProdText = Color(0xFFFCA5A5),
    envDevBg = Color(0xFF132C28),
    envDevText = Color(0xFF6EE7B7),
    envStageBg = Color(0xFF2D2415),
    envStageText = Color(0xFFFCD34D),
    envOtherBg = Color(0xFF172947),
    envOtherText = Color(0xFF93C5FD)
)

val LightSemanticColors = SemanticColors(
    isDark = false,
    timerNormal = Color(0xFF1D4ED8),
    timerWarning = Color(0xFFB45309),
    timerDanger = Color(0xFFDC2626),
    success = Color(0xFF047857),
    onSuccess = Color(0xFFFFFFFF),
    warningBg = Color(0xFFFEF3C7),
    warningText = Color(0xFF92400E),
    errorText = Color(0xFFB91C1C),
    borderSubtle = Color(0xFFE2E8F0),
    surfaceElevated = Color(0xFFFFFFFF),
    scrim = Color(0x730B111E),
    envProdBg = Color(0xFFFEE2E2),
    envProdText = Color(0xFFB91C1C),
    envDevBg = Color(0xFFDCFCE7),
    envDevText = Color(0xFF047857),
    envStageBg = Color(0xFFFEF3C7),
    envStageText = Color(0xFFB45309),
    envOtherBg = Color(0xFFDBEAFE),
    envOtherText = Color(0xFF1D4ED8)
)

val LocalSemanticColors = staticCompositionLocalOf { DarkSemanticColors }
