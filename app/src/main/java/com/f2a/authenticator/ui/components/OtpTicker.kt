package com.f2a.authenticator.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.totp.OtpEngine
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Type

/**
 * 纯函数计算当前/下一/上一周期验证码（供点击复制按需调用，不在组合期直接读取高频时钟）。
 */
fun computeTokenOtpCode(
    token: AuthToken,
    cycleOffset: Int = 0,
    nowMs: Long = System.currentTimeMillis()
): String {
    if (token.secretInvalid) return ""
    if (token.type == TokenType.HOTP) {
        val targetCounter = (token.counter + cycleOffset).coerceAtLeast(0L)
        return OtpEngine.generateHotp(token.secret, targetCounter, token.digits, token.algorithm)
    }
    val isSteam = token.type == TokenType.STEAM
    return when {
        cycleOffset < 0 -> OtpEngine.generatePreviousTotp(token.secret, token.period, token.digits, token.algorithm, isSteam, nowMs)
        cycleOffset > 0 -> OtpEngine.generateNextTotp(token.secret, token.period, token.digits, token.algorithm, isSteam, nowMs)
        else -> OtpEngine.generateTotp(token.secret, token.period, token.digits, token.algorithm, isSteam, nowMs)
    }
}

fun splitOtpParts(code: String): Pair<String, String> = when (code.length) {
    6 -> code.substring(0, 3) to code.substring(3, 6)
    8 -> code.substring(0, 4) to code.substring(4, 8)
    else -> code to ""
}

/**
 * V2-UI-04：高频时钟隔离倒计时圆环叶子组件。
 * CircularProgressIndicator 的 progress lambda 仅在 Draw 阶段读取 nowMsProvider()，0 重组；
 * 文本秒数通过 derivedStateOf 降频至 <= 1Hz。
 */
@Composable
fun OtpRingTicker(
    period: Int,
    nowMsProvider: () -> Long,
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
    strokeWidth: Dp = 3.dp
) {
    val semantic = LocalSemanticColors.current
    val remainingSeconds by remember(period) {
        derivedStateOf { OtpEngine.getRemainingSeconds(period, nowMsProvider()) }
    }
    val timerColor = when {
        remainingSeconds <= 5 -> semantic.timerDanger
        remainingSeconds <= 10 -> semantic.timerWarning
        else -> semantic.timerNormal
    }

    Box(contentAlignment = Alignment.Center, modifier = modifier.size(size)) {
        CircularProgressIndicator(
            progress = { OtpEngine.getRemainingProgress(period, nowMsProvider()) },
            modifier = Modifier.size(size),
            color = timerColor,
            strokeWidth = strokeWidth,
            trackColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
        Text(
            text = "$remainingSeconds",
            style = Type.CodeMonoS,
            color = timerColor
        )
    }
}

/**
 * V2-UI-04 + V2-UI-21：列表账号行验证码叶子组件。
 * 隔离 100ms 时钟，仅在步进切换或颜色档位切换时局部刷新；TalkBack 逐位空格播报。
 */
@Composable
fun OtpRowCodeDisplay(
    token: AuthToken,
    showNextCodePreview: Boolean,
    nowMsProvider: () -> Long,
    modifier: Modifier = Modifier
) {
    val semantic = LocalSemanticColors.current
    val currentStep by remember(token.period, token.type, token.counter) {
        derivedStateOf {
            if (token.type == TokenType.HOTP) token.counter
            else OtpEngine.getCurrentStep(token.period, 0L, nowMsProvider())
        }
    }
    val remainingSeconds by remember(token.period, token.type) {
        derivedStateOf {
            if (token.type == TokenType.HOTP) 0
            else OtpEngine.getRemainingSeconds(token.period, nowMsProvider())
        }
    }
    val timerColor = if (token.type == TokenType.HOTP) {
        semantic.timerNormal
    } else {
        when {
            remainingSeconds <= 5 -> semantic.timerDanger
            remainingSeconds <= 10 -> semantic.timerWarning
            else -> semantic.timerNormal
        }
    }

    val displayCode = remember(
        token.secret,
        currentStep,
        token.counter,
        token.type,
        token.digits,
        token.algorithm,
        token.secretInvalid,
        showNextCodePreview
    ) {
        if (token.secretInvalid) ""
        else if (token.type == TokenType.HOTP) {
            val target = if (showNextCodePreview) token.counter + 1 else token.counter
            OtpEngine.generateHotp(token.secret, target, token.digits, token.algorithm)
        } else {
            val step = if (showNextCodePreview) currentStep + 1 else currentStep
            if (token.type == TokenType.STEAM) {
                OtpEngine.generateSteamCode(token.secret, step)
            } else {
                OtpEngine.generateOtp(token.secret, step, token.digits, token.algorithm)
            }
        }
    }

    val (part1, part2) = splitOtpParts(displayCode)
    val spokenDigits = remember(displayCode) { displayCode.toCharArray().joinToString(" ") }

    Row(
        modifier = modifier.semantics {
            contentDescription = when {
                token.secretInvalid -> "密钥损坏，请重新导入"
                token.type == TokenType.HOTP -> "动态验证码 $spokenDigits"
                else -> "动态验证码 $spokenDigits，剩余 $remainingSeconds 秒"
            }
        },
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (token.secretInvalid) {
            Text(
                text = "⚠ 密钥损坏，请重新导入",
                style = Type.BodyM,
                fontWeight = FontWeight.Bold,
                color = semantic.errorText
            )
        } else {
            val codeColor = if (showNextCodePreview) MaterialTheme.colorScheme.secondary else timerColor
            Text(
                text = part1,
                style = Type.CodeRow,
                maxLines = 1,
                softWrap = false,
                color = codeColor
            )
            if (part2.isNotEmpty()) {
                Spacer(modifier = Modifier.width(Space.S))
                Text(
                    text = part2,
                    style = Type.CodeRow,
                    maxLines = 1,
                    softWrap = false,
                    color = codeColor
                )
            }
            if (showNextCodePreview) {
                Spacer(modifier = Modifier.width(Space.S))
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(Radius.XS))
                        .background(MaterialTheme.colorScheme.secondary.copy(alpha = 0.15f))
                        .padding(horizontal = Space.HS, vertical = Space.XXS)
                ) {
                    Text(
                        text = "下个周期",
                        style = Type.Caption,
                        color = MaterialTheme.colorScheme.secondary
                    )
                }
            }
        }
    }
}

/**
 * 详情页大字 Hero 验证码（CodeHero = 48.sp）与倒计时隔离组件。
 */
@Composable
fun OtpHeroCodeDisplay(
    token: AuthToken,
    cycleOffset: Int,
    nowMsProvider: () -> Long,
    modifier: Modifier = Modifier
) {
    val semantic = LocalSemanticColors.current
    val currentStep by remember(token.period, token.type, token.counter) {
        derivedStateOf {
            if (token.type == TokenType.HOTP) token.counter
            else OtpEngine.getCurrentStep(token.period, 0L, nowMsProvider())
        }
    }
    val remainingSeconds by remember(token.period, token.type) {
        derivedStateOf {
            if (token.type == TokenType.HOTP) 0
            else OtpEngine.getRemainingSeconds(token.period, nowMsProvider())
        }
    }
    val timerColor = if (token.type == TokenType.HOTP) {
        semantic.timerNormal
    } else {
        when {
            remainingSeconds <= 5 -> semantic.timerDanger
            remainingSeconds <= 10 -> semantic.timerWarning
            else -> semantic.timerNormal
        }
    }

    val currentOtp = remember(
        token.secret,
        currentStep,
        cycleOffset,
        token.counter,
        token.type,
        token.digits,
        token.algorithm,
        token.secretInvalid
    ) {
        if (token.secretInvalid) ""
        else if (token.type == TokenType.HOTP) {
            OtpEngine.generateHotp(token.secret, token.counter, token.digits, token.algorithm)
        } else {
            val step = (currentStep + cycleOffset).coerceAtLeast(0L)
            if (token.type == TokenType.STEAM) {
                OtpEngine.generateSteamCode(token.secret, step)
            } else {
                OtpEngine.generateOtp(token.secret, step, token.digits, token.algorithm)
            }
        }
    }

    val (part1, part2) = splitOtpParts(currentOtp)
    val spokenDigits = remember(currentOtp) { currentOtp.toCharArray().joinToString(" ") }

    if (token.secretInvalid) {
        Text(
            text = "⚠ 密钥损坏，无法生成验证码\n请重新导入该凭据",
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
            color = semantic.errorText,
            textAlign = TextAlign.Center,
            modifier = modifier
        )
    } else {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = modifier.semantics {
                contentDescription = if (token.type == TokenType.HOTP) {
                    "动态验证码 $spokenDigits"
                } else {
                    "动态验证码 $spokenDigits，剩余 $remainingSeconds 秒"
                }
            }
        ) {
            val codeColor = if (cycleOffset != 0) MaterialTheme.colorScheme.secondary else timerColor
            Text(
                text = part1,
                style = Type.CodeHero,
                maxLines = 1,
                softWrap = false,
                textAlign = TextAlign.Center,
                color = codeColor
            )
            if (part2.isNotEmpty()) {
                Spacer(modifier = Modifier.width(Space.M))
                Text(
                    text = part2,
                    style = Type.CodeHero,
                    maxLines = 1,
                    softWrap = false,
                    textAlign = TextAlign.Center,
                    color = codeColor
                )
            }
        }
    }
}
