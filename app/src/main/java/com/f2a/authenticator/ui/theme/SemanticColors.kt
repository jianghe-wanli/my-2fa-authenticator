package com.f2a.authenticator.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * 深浅色自适应语义色表（V2-UI-07：保证浅色模式全部文字/角标对比度 ≥ 4.5:1）。
 */
@Immutable
data class SemanticColors(
    val timerNormal: Color,
    val timerWarning: Color,
    val timerDanger: Color,
    val success: Color,
    val onSuccess: Color,
    val errorText: Color,
    val borderSubtle: Color,
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
    timerNormal = Color(0xFF06B6D4),
    timerWarning = Color(0xFFF59E0B),
    timerDanger = Color(0xFFFF3366),
    success = Color(0xFF34D399),
    onSuccess = Color(0xFF032319),
    errorText = Color(0xFFFF8095),
    borderSubtle = Color(0x26FFFFFF),
    scrim = Color(0x8C000000),
    envProdBg = Color(0x33EF4444),
    envProdText = Color(0xFFFF6B6B),
    envDevBg = Color(0x3310B981),
    envDevText = Color(0xFF34D399),
    envStageBg = Color(0x33F59E0B),
    envStageText = Color(0xFFFBBF24),
    envOtherBg = Color(0x333B82F6),
    envOtherText = Color(0xFF60A5FA)
)

val LightSemanticColors = SemanticColors(
    timerNormal = Color(0xFF0369A1),
    timerWarning = Color(0xFFB45309),
    timerDanger = Color(0xFFDC2626),
    success = Color(0xFF047857),
    onSuccess = Color(0xFFFFFFFF),
    errorText = Color(0xFFDC2626),
    borderSubtle = Color(0xFFE2E8F0),
    scrim = Color(0x73000000),
    envProdBg = Color(0x1FDC2626),
    envProdText = Color(0xFFB91C1C),
    envDevBg = Color(0x1F059669),
    envDevText = Color(0xFF047857),
    envStageBg = Color(0x1FD97706),
    envStageText = Color(0xFFB45309),
    envOtherBg = Color(0x1F2563EB),
    envOtherText = Color(0xFF1D4ED8)
)

val LocalSemanticColors = staticCompositionLocalOf { DarkSemanticColors }
