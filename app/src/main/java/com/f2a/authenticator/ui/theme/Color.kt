package com.f2a.authenticator.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

// Precision Deep-Blue Vault · 深海精密暗夜调色板（Deep Marine Slate）
val NavyBg = Color(0xFF0B111E)
val NavySurface = Color(0xFF111A2B)
val NavySurfaceElevated = Color(0xFF182338)
val NavySurfaceContainerHigh = Color(0xFF1B2840)
val NavyBorder = Color(0xFF25344F)
val NavyBorderSubtle = Color(0xFF1D2A42)

val CobaltPrimaryDark = Color(0xFF5A9BFF)
val SteelBlueSecondaryDark = Color(0xFF7DA8E8)
val SlateTealTertiaryDark = Color(0xFF4B9DA9)

// Precision Deep-Blue Vault · 清爽高对比浅色板（Crisp Porcelain & Navy）
val PorcelainBg = Color(0xFFF3F6FA)
val PorcelainSurface = Color(0xFFFFFFFF)
val PorcelainSurfaceVariant = Color(0xFFEBF0F7)
val PorcelainBorder = Color(0xFFCBD5E1)
val PorcelainBorderSubtle = Color(0xFFE2E8F0)

val CobaltPrimaryLight = Color(0xFF1D4ED8)
val SteelBlueSecondaryLight = Color(0xFF335C99)
val SlateTealTertiaryLight = Color(0xFF0F766E)

// 深色 Material3 语义槽位
val DarkColorScheme = darkColorScheme(
    primary = CobaltPrimaryDark,
    onPrimary = Color(0xFF061836),
    primaryContainer = Color(0xFF163059),
    onPrimaryContainer = Color(0xFFD6E6FF),
    secondary = SteelBlueSecondaryDark,
    onSecondary = Color(0xFF091933),
    secondaryContainer = Color(0xFF1C2E4A),
    onSecondaryContainer = Color(0xFFCFE0FA),
    tertiary = SlateTealTertiaryDark,
    onTertiary = Color(0xFF051F24),
    tertiaryContainer = Color(0xFF15343B),
    onTertiaryContainer = Color(0xFFC7EBF0),
    error = Color(0xFFF87171),
    onError = Color(0xFF2B0909),
    errorContainer = Color(0xFF4A171C),
    onErrorContainer = Color(0xFFFAD4D4),
    background = NavyBg,
    onBackground = Color(0xFFEEF3FA),
    surface = NavySurface,
    onSurface = Color(0xFFF1F5FB),
    surfaceVariant = NavySurfaceElevated,
    onSurfaceVariant = Color(0xFF94A3B8),
    surfaceContainerLowest = Color(0xFF080D17),
    surfaceContainerLow = NavyBg,
    surfaceContainer = NavySurface,
    surfaceContainerHigh = NavySurfaceElevated,
    surfaceContainerHighest = NavySurfaceContainerHigh,
    surfaceTint = CobaltPrimaryDark,
    outline = NavyBorder,
    outlineVariant = NavyBorderSubtle,
    inverseSurface = Color(0xFFEAF0F8),
    inverseOnSurface = NavySurface,
    scrim = Color(0xFF050912)
)

// 浅色 Material3 语义槽位
val LightColorScheme = lightColorScheme(
    primary = CobaltPrimaryLight,
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFDBEAFE),
    onPrimaryContainer = Color(0xFF1E3A8A),
    secondary = SteelBlueSecondaryLight,
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFE2EBF8),
    onSecondaryContainer = Color(0xFF162D52),
    tertiary = SlateTealTertiaryLight,
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFCCFBF1),
    onTertiaryContainer = Color(0xFF115E59),
    error = Color(0xFFDC2626),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF7F1D1D),
    background = PorcelainBg,
    onBackground = Color(0xFF0F172A),
    surface = PorcelainSurface,
    onSurface = Color(0xFF0F172A),
    surfaceVariant = PorcelainSurfaceVariant,
    onSurfaceVariant = Color(0xFF475569),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = PorcelainBg,
    surfaceContainer = PorcelainSurface,
    surfaceContainerHigh = PorcelainSurfaceVariant,
    surfaceContainerHighest = Color(0xFFE2E8F0),
    surfaceTint = CobaltPrimaryLight,
    outline = PorcelainBorder,
    outlineVariant = PorcelainBorderSubtle,
    inverseSurface = Color(0xFF0F172A),
    inverseOnSurface = Color(0xFFF3F6FA),
    scrim = Color(0xFF0B111E)
)
