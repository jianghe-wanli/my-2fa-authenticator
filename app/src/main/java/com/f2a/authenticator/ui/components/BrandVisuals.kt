package com.f2a.authenticator.ui.components

import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import com.f2a.authenticator.ui.theme.SemanticColors
import java.util.Locale

fun parseHexColor(hex: String): Color {
    return try {
        Color(android.graphics.Color.parseColor(hex))
    } catch (_: Exception) {
        Color(0xFF6366F1)
    }
}

fun accessibleTagTextColor(tagColor: Color, isDarkTheme: Boolean): Color {
    if (isDarkTheme) return tagColor
    return if (tagColor.luminance() > 0.30f) {
        lerp(tagColor, Color(0xFF0F172A), 0.45f)
    } else {
        tagColor
    }
}

fun issuerAvatarLabel(issuer: String, fallbackAccount: String = ""): String {
    val cleanIssuer = issuer.trim()
    if (cleanIssuer.isNotEmpty()) return cleanIssuer.take(2).uppercase(Locale.US)
    val cleanAcc = fallbackAccount.trim()
    if (cleanAcc.isNotEmpty()) return cleanAcc.take(2).uppercase(Locale.US)
    return "2F"
}

fun getBrandGradient(issuer: String): Brush {
    val lower = issuer.lowercase(Locale.US)
    return when {
        lower.contains("aws") || lower.contains("amazon") -> Brush.linearGradient(
            listOf(Color(0xFFFF9900), Color(0xFFFF6600))
        )
        lower.contains("github") -> Brush.linearGradient(
            listOf(Color(0xFF333333), Color(0xFF181717))
        )
        lower.contains("google") -> Brush.linearGradient(
            listOf(Color(0xFF4285F4), Color(0xFF34A853))
        )
        lower.contains("microsoft") || lower.contains("azure") -> Brush.linearGradient(
            listOf(Color(0xFF0078D4), Color(0xFF005A9E))
        )
        lower.contains("cloudflare") -> Brush.linearGradient(
            listOf(Color(0xFFF38020), Color(0xFFFA541C))
        )
        lower.contains("steam") -> Brush.linearGradient(
            listOf(Color(0xFF171A21), Color(0xFF1B2838))
        )
        else -> Brush.linearGradient(
            listOf(Color(0xFF6366F1), Color(0xFF4F46E5))
        )
    }
}

fun getEnvColors(tenantEnv: String, semantic: SemanticColors): Pair<Color, Color> {
    val lower = tenantEnv.lowercase(Locale.US)
    return when {
        lower.contains("prod") || lower.contains("生产") || lower.contains("主") -> {
            semantic.envProdBg to semantic.envProdText
        }
        lower.contains("dev") || lower.contains("开发") || lower.contains("测试") -> {
            semantic.envDevBg to semantic.envDevText
        }
        lower.contains("stage") || lower.contains("预发") || lower.contains("灰度") -> {
            semantic.envStageBg to semantic.envStageText
        }
        else -> {
            semantic.envOtherBg to semantic.envOtherText
        }
    }
}
