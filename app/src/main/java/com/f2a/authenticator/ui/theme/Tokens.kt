package com.f2a.authenticator.ui.theme

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * 设计 Token 体系（纯 Kotlin 常量对象，零新依赖）。
 */
object Space {
    val XXS = 2.dp
    val XS = 4.dp
    val HS = 6.dp
    val S = 8.dp
    val MS = 10.dp
    val M = 12.dp
    val ML = 14.dp
    val L = 16.dp
    val XL = 20.dp
    val XXL = 24.dp
    val X3L = 32.dp
    val X4L = 40.dp
    val X5L = 48.dp
    val BottomListPad = 96.dp
}

object Radius {
    val XS = 6.dp
    val S = 10.dp
    val M = 12.dp
    val L = 18.dp
    val XL = 24.dp
    val Full = 999.dp
}

object IconSize {
    val XS = 16.dp
    val S = 18.dp
    val M = 20.dp
    val L = 22.dp
    val XL = 24.dp
    val Hero = 48.dp
    val LockShield = 36.dp
    val LockKey = 72.dp
}

object Type {
    // 安全红线：详情页大字验证码 CodeHero = 48.sp (>= 44.sp)
    val CodeHero = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontFeatureSettings = "tnum",
        fontWeight = FontWeight.Black,
        fontSize = 48.sp,
        lineHeight = 56.sp,
        letterSpacing = 6.sp
    )

    val CodeRow = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontFeatureSettings = "tnum",
        fontWeight = FontWeight.Black,
        fontSize = 26.sp,
        lineHeight = 32.sp,
        letterSpacing = 2.sp
    )

    val CodeMonoS = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 12.sp,
        lineHeight = 14.sp
    )

    val TitlePage = TextStyle(
        fontWeight = FontWeight.Black,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        letterSpacing = 0.5.sp
    )

    val TitleSection = TextStyle(
        fontWeight = FontWeight.ExtraBold,
        fontSize = 18.sp,
        lineHeight = 24.sp
    )

    val TitleCard = TextStyle(
        fontWeight = FontWeight.ExtraBold,
        fontSize = 16.sp,
        lineHeight = 22.sp,
        letterSpacing = 0.2.sp
    )

    val BodyL = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 22.sp
    )

    val BodyM = TextStyle(
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp
    )

    val BodyS = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp
    )

    val Label = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 11.sp,
        lineHeight = 14.sp,
        letterSpacing = 0.5.sp
    )

    val Caption = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 10.sp,
        lineHeight = 12.sp
    )
}

object Motion {
    const val instant = 0
    const val fast = 120
    const val base = 200
    const val slow = 280
    const val errorShake = 320
    const val hold = 1500L

    val EaseStandard = CubicBezierEasing(0.2f, 0f, 0f, 1f)
    val EaseDecel = CubicBezierEasing(0.05f, 0.7f, 0.1f, 1f)
    val EaseAccel = CubicBezierEasing(0.3f, 0f, 0.8f, 0.15f)
}

object Touch {
    val MinTarget = 48.dp
    val SegmentedHeight = 40.dp
    val CompactChipHeight = 34.dp
}

val AppTypography = Typography(
    headlineMedium = Type.TitlePage,
    headlineSmall = Type.TitleSection,
    titleLarge = Type.TitleSection,
    titleMedium = Type.TitleCard,
    titleSmall = Type.TitleCard,
    bodyLarge = Type.BodyL,
    bodyMedium = Type.BodyM,
    bodySmall = Type.BodyS,
    labelLarge = Type.BodyL,
    labelMedium = Type.Label,
    labelSmall = Type.Caption
)

val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(Radius.XS),
    small = RoundedCornerShape(Radius.S),
    medium = RoundedCornerShape(Radius.M),
    large = RoundedCornerShape(Radius.L),
    extraLarge = RoundedCornerShape(Radius.XL)
)
