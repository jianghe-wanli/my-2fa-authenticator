package com.f2a.authenticator.ui.screens.dialogs

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.Motion
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AddTokenAdvancedSection(
    expanded: Boolean,
    onToggle: () -> Unit,
    selectedType: TokenType,
    onTypeChange: (TokenType) -> Unit,
    selectedAlgorithm: String,
    onAlgorithmChange: (String) -> Unit,
    selectedDigits: Int,
    onDigitsChange: (Int) -> Unit,
    selectedPeriod: Int,
    onPeriodChange: (Int) -> Unit,
    selectedCounter: Long,
    onCounterChange: (Long) -> Unit
) {
    val rotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        animationSpec = tween(durationMillis = Motion.base, easing = Motion.EaseStandard),
        label = "adv_arrow"
    )
    Column(modifier = Modifier.fillMaxWidth()) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = Touch.MinTarget)
                .clickable(onClick = onToggle)
                .padding(vertical = Space.S),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = Space.S)) {
                Text("高级选项（一般无需修改）", style = Type.BodyM, fontWeight = FontWeight.Bold)
                Text("类型 (TOTP/HOTP/Steam) · 算法 · 位数 · 周期", style = Type.BodyS, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Icon(
                Icons.Default.ExpandMore,
                contentDescription = if (expanded) "收起高级选项" else "展开高级选项",
                modifier = Modifier
                    .rotate(rotation)
                    .size(IconSize.L),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        AnimatedVisibility(
            visible = expanded,
            enter = expandVertically(tween(Motion.slow, easing = Motion.EaseStandard)) +
                fadeIn(tween(Motion.slow, easing = Motion.EaseStandard)),
            exit = shrinkVertically(tween(Motion.slow, easing = Motion.EaseStandard)) +
                fadeOut(tween(Motion.slow, easing = Motion.EaseStandard))
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text("令牌类型", style = Type.BodyS, fontWeight = FontWeight.Bold)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(Space.S)) {
                    listOf(
                        TokenType.TOTP to "标准 TOTP",
                        TokenType.HOTP to "计数 HOTP",
                        TokenType.STEAM to "Steam 令牌"
                    ).forEach { (type, label) ->
                        FilterChip(
                            selected = selectedType == type,
                            onClick = { onTypeChange(type) },
                            label = { Text(label, style = Type.BodyS) }
                        )
                    }
                }

                if (selectedType != TokenType.STEAM) {
                    Spacer(modifier = Modifier.height(Space.S))
                    Text("算法", style = Type.BodyS, fontWeight = FontWeight.Bold)
                    Row(horizontalArrangement = Arrangement.spacedBy(Space.S)) {
                        listOf("SHA1", "SHA256", "SHA512").forEach { alg ->
                            FilterChip(
                                selected = selectedAlgorithm == alg,
                                onClick = { onAlgorithmChange(alg) },
                                label = { Text(alg, style = Type.BodyS) }
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(Space.S))
                    Text("位数", style = Type.BodyS, fontWeight = FontWeight.Bold)
                    Row(horizontalArrangement = Arrangement.spacedBy(Space.S)) {
                        listOf(6, 8).forEach { d ->
                            FilterChip(
                                selected = selectedDigits == d,
                                onClick = { onDigitsChange(d) },
                                label = { Text("$d 位", style = Type.BodyS) }
                            )
                        }
                    }
                }

                if (selectedType == TokenType.TOTP) {
                    Spacer(modifier = Modifier.height(Space.S))
                    Text("刷新周期 (秒)", style = Type.BodyS, fontWeight = FontWeight.Bold)
                    Row(horizontalArrangement = Arrangement.spacedBy(Space.S)) {
                        listOf(30, 60).forEach { p ->
                            FilterChip(
                                selected = selectedPeriod == p,
                                onClick = { onPeriodChange(p) },
                                label = { Text("${p}s", style = Type.BodyS) }
                            )
                        }
                    }
                }

                if (selectedType == TokenType.HOTP) {
                    Spacer(modifier = Modifier.height(Space.S))
                    Text("初始计数 (counter)", style = Type.BodyS, fontWeight = FontWeight.Bold)
                    OutlinedTextField(
                        value = selectedCounter.toString(),
                        onValueChange = { v -> v.toLongOrNull()?.coerceAtLeast(0L)?.let(onCounterChange) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(Radius.S)
                    )
                }
                Spacer(modifier = Modifier.height(Space.S))
            }
        }
    }
}
