package com.f2a.authenticator.ui.components

import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import com.f2a.authenticator.ui.theme.SemanticColors
import java.util.Locale
import kotlin.math.abs

private val FallbackCobalt = Color(0xFF1D4ED8)

// 确定性兜底品牌渐变色板（克制深海蓝/钢蓝/钛青/沉稳商务色，零霓虹紫）
private val DeterministicBrandPalettes: List<Pair<Color, Color>> = listOf(
    Color(0xFF234B8C) to Color(0xFF173363),
    Color(0xFF1E5B70) to Color(0xFF143F4F),
    Color(0xFF2D4A6D) to Color(0xFF1D324D),
    Color(0xFF335C99) to Color(0xFF213F6B),
    Color(0xFF1B645A) to Color(0xFF12463F),
    Color(0xFF475569) to Color(0xFF2B3544),
    Color(0xFF2B547E) to Color(0xFF1B3754),
    Color(0xFF3B4F6B) to Color(0xFF253447)
)

fun parseHexColor(hex: String): Color {
    return try {
        Color(android.graphics.Color.parseColor(hex))
    } catch (_: Exception) {
        FallbackCobalt
    }
}

fun accessibleTagTextColor(tagColor: Color, isDarkTheme: Boolean): Color {
    return if (isDarkTheme) {
        if (tagColor.luminance() < 0.28f) {
            lerp(tagColor, Color(0xFFE2E8F0), 0.45f)
        } else {
            tagColor
        }
    } else {
        if (tagColor.luminance() > 0.30f) {
            lerp(tagColor, Color(0xFF0F172A), 0.48f)
        } else {
            tagColor
        }
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
    val lower = issuer.trim().lowercase(Locale.US)
    val pair: Pair<Color, Color> = when {
        lower.contains("aws") || lower.contains("amazon") -> Color(0xFFD97706) to Color(0xFFB45309)
        lower.contains("github") -> Color(0xFF2D333B) to Color(0xFF1C2128)
        lower.contains("gitlab") -> Color(0xFFD95B26) to Color(0xFFB34014)
        lower.contains("google") || lower.contains("gmail") -> Color(0xFF2563EB) to Color(0xFF1D4ED8)
        lower.contains("microsoft") || lower.contains("azure") || lower.contains("office") || lower.contains("m365") ->
            Color(0xFF0276CC) to Color(0xFF005499)
        lower.contains("apple") || lower.contains("icloud") -> Color(0xFF334155) to Color(0xFF1E293B)
        lower.contains("openai") || lower.contains("chatgpt") -> Color(0xFF0F766E) to Color(0xFF115E59)
        lower.contains("anthropic") || lower.contains("claude") -> Color(0xFFB4693E) to Color(0xFF8C4E2B)
        lower.contains("cloudflare") -> Color(0xFFD97724) to Color(0xFFB85814)
        lower.contains("discord") -> Color(0xFF4752C4) to Color(0xFF37409E)
        lower.contains("notion") -> Color(0xFF2E3440) to Color(0xFF1F242D)
        lower.contains("docker") -> Color(0xFF0B6EBD) to Color(0xFF08528F)
        lower.contains("vercel") -> Color(0xFF27272A) to Color(0xFF18181B)
        lower.contains("alibaba") || lower.contains("aliyun") || lower.contains("阿里") ->
            Color(0xFFD9681A) to Color(0xFFB44D0E)
        lower.contains("tencent") || lower.contains("wechat") || lower.contains("微信") || lower.contains("腾讯") ->
            Color(0xFF15803D) to Color(0xFF166534)
        lower.contains("binance") || lower.contains("币安") -> Color(0xFFC48A10) to Color(0xFF9B6B08)
        lower.contains("okx") || lower.contains("欧易") -> Color(0xFF262D3A) to Color(0xFF161B24)
        lower.contains("coinbase") -> Color(0xFF1652F0) to Color(0xFF0E3BB5)
        lower.contains("bitwarden") -> Color(0xFF175DDC) to Color(0xFF1043A3)
        lower.contains("1password") -> Color(0xFF1A64B8) to Color(0xFF124685)
        lower.contains("steam") -> Color(0xFF1B2838) to Color(0xFF111A26)
        lower.contains("linear") -> Color(0xFF34497A) to Color(0xFF233357)
        lower.contains("tailscale") -> Color(0xFF2E4057) to Color(0xFF1F2D3D)
        lower.contains("stripe") -> Color(0xFF3B5B9D) to Color(0xFF294175)
        lower.contains("paypal") -> Color(0xFF00457C) to Color(0xFF003057)
        lower.contains("synology") || lower.contains("群晖") -> Color(0xFF28558A) to Color(0xFF1B3B63)
        lower.contains("huawei") || lower.contains("华为") -> Color(0xFFB91C1C) to Color(0xFF991B1B)
        else -> {
            val idx = if (lower.isEmpty()) 0 else abs(lower.hashCode()) % DeterministicBrandPalettes.size
            DeterministicBrandPalettes[idx]
        }
    }
    return Brush.linearGradient(listOf(pair.first, pair.second))
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
