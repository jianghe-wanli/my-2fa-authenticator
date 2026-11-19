package com.f2a.authenticator.ui.screens.settings

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.f2a.authenticator.security.HealthSeverity
import com.f2a.authenticator.security.VaultHealthReport
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.Motion
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

@Composable
fun VaultHealthCard(
    report: VaultHealthReport,
    onAction: (String) -> Unit
) {
    val semantic = LocalSemanticColors.current
    val haptic = LocalHapticFeedback.current
    val hasIssues = report.items.any { it.severity != HealthSeverity.OK }
    var expanded by rememberSaveable { mutableStateOf(hasIssues) }

    val scoreColor = when {
        report.score >= 85 -> semantic.success
        report.score >= 60 -> semantic.timerWarning
        else -> semantic.timerDanger
    }

    val rotationState by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        animationSpec = tween(durationMillis = Motion.base, easing = Motion.EaseStandard),
        label = "health_arrow"
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, semantic.borderSubtle, RoundedCornerShape(Radius.L)),
        shape = RoundedCornerShape(Radius.L),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = if (semantic.isDark) 0.dp else 0.5.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        expanded = !expanded
                    }
                    .padding(Space.L),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(46.dp)
                        .clip(CircleShape)
                        .background(scoreColor.copy(alpha = 0.14f))
                        .border(1.5.dp, scoreColor.copy(alpha = 0.55f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "${report.score}",
                        style = Type.TitleSection,
                        fontWeight = FontWeight.Bold,
                        color = scoreColor
                    )
                }

                Spacer(modifier = Modifier.width(Space.M))

                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.VerifiedUser,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(IconSize.XS)
                        )
                        Spacer(modifier = Modifier.width(Space.XS))
                        Text(
                            text = "离线安全体检中心",
                            style = Type.TitleCard,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    Spacer(modifier = Modifier.height(Space.XXS))
                    val riskCount = report.items.count { it.severity != HealthSeverity.OK }
                    Text(
                        text = if (riskCount == 0) {
                            "核心防护已全部就绪 · 本地零联网评估"
                        } else {
                            "发现 $riskCount 项待优化风险 · 点击展开修复"
                        },
                        style = Type.BodyS,
                        color = if (riskCount == 0) semantic.success else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Icon(
                    imageVector = Icons.Default.ExpandMore,
                    contentDescription = if (expanded) "收起体检详情" else "展开体检详情",
                    modifier = Modifier
                        .rotate(rotationState)
                        .size(IconSize.L),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically(tween(Motion.slow, easing = Motion.EaseStandard)) +
                    fadeIn(tween(Motion.base, easing = Motion.EaseStandard)),
                exit = shrinkVertically(tween(Motion.slow, easing = Motion.EaseStandard)) +
                    fadeOut(tween(Motion.fast, easing = Motion.EaseStandard))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = Space.L, end = Space.L, bottom = Space.M),
                    verticalArrangement = Arrangement.spacedBy(Space.S)
                ) {
                    HorizontalDivider(color = semantic.borderSubtle)
                    Spacer(modifier = Modifier.height(Space.XXS))

                    report.items.forEach { item ->
                        val itemColor = when (item.severity) {
                            HealthSeverity.CRITICAL -> semantic.timerDanger
                            HealthSeverity.WARNING -> semantic.timerWarning
                            HealthSeverity.OK -> semantic.success
                        }
                        val itemIcon = when (item.severity) {
                            HealthSeverity.CRITICAL -> Icons.Default.ErrorOutline
                            HealthSeverity.WARNING -> Icons.Default.WarningAmber
                            HealthSeverity.OK -> Icons.Default.CheckCircle
                        }

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(Radius.M))
                                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f))
                                .padding(horizontal = Space.M, vertical = Space.S),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = itemIcon,
                                contentDescription = null,
                                tint = itemColor,
                                modifier = Modifier.size(IconSize.M)
                            )
                            Spacer(modifier = Modifier.width(Space.MS))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = item.title,
                                    style = Type.BodyM,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = item.detail,
                                    style = Type.Caption,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            if (item.actionKey != null) {
                                TextButton(
                                    onClick = { onAction(item.actionKey!!) },
                                    contentPadding = PaddingValues(horizontal = Space.S, vertical = Space.XS)
                                ) {
                                    Text(
                                        text = if (item.severity == HealthSeverity.OK) "设置" else "修复",
                                        style = Type.Label,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SettingsAccordionCard(
    title: String,
    subtitle: String,
    icon: ImageVector,
    iconTint: Color = MaterialTheme.colorScheme.primary,
    isExpanded: Boolean,
    onToggle: () -> Unit,
    danger: Boolean = false,
    content: @Composable () -> Unit
) {
    val haptic = LocalHapticFeedback.current
    val semantic = LocalSemanticColors.current
    val rotationState by animateFloatAsState(
        targetValue = if (isExpanded) 180f else 0f,
        animationSpec = tween(durationMillis = Motion.base, easing = Motion.EaseStandard),
        label = "arrow"
    )
    val borderColor = if (danger) {
        MaterialTheme.colorScheme.error.copy(alpha = 0.4f)
    } else {
        semantic.borderSubtle
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, borderColor, RoundedCornerShape(Radius.L)),
        shape = RoundedCornerShape(Radius.L),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = if (semantic.isDark) 0.dp else 0.5.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onToggle()
                    }
                    .padding(Space.L),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(Radius.S))
                        .background(iconTint.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(icon, contentDescription = null, tint = iconTint, modifier = Modifier.size(IconSize.M))
                }
                Spacer(modifier = Modifier.width(Space.M))
                Column(modifier = Modifier.weight(1f)) {
                    Text(text = title, style = Type.TitleCard, color = MaterialTheme.colorScheme.onSurface)
                    Spacer(modifier = Modifier.height(Space.XXS))
                    Text(text = subtitle, style = Type.BodyS, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Icon(
                    imageVector = Icons.Default.ExpandMore,
                    contentDescription = if (isExpanded) "收起" else "展开",
                    modifier = Modifier
                        .rotate(rotationState)
                        .size(IconSize.L),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically(tween(Motion.slow, easing = Motion.EaseStandard)) +
                    fadeIn(tween(Motion.base, easing = Motion.EaseStandard)),
                exit = shrinkVertically(tween(Motion.slow, easing = Motion.EaseStandard)) +
                    fadeOut(tween(Motion.fast, easing = Motion.EaseStandard))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = Space.L, vertical = Space.M)
                ) {
                    HorizontalDivider(color = semantic.borderSubtle)
                    Spacer(modifier = Modifier.height(Space.M))
                    content()
                }
            }
        }
    }
}

@Composable
fun SettingRow(
    title: String,
    description: String? = null,
    control: @Composable () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = Space.M),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = Type.BodyM, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
            if (!description.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(Space.XXS))
                Text(text = description, style = Type.BodyS, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Spacer(modifier = Modifier.width(Space.M))
        control()
    }
}

@Composable
fun SettingDivider() {
    HorizontalDivider(color = LocalSemanticColors.current.borderSubtle)
}

@Composable
fun SelfDestructHoldButton(
    holdMillis: Int = 3000,
    onHoldComplete: () -> Unit
) {
    val progress = remember { Animatable(0f) }
    val scope = rememberCoroutineScope()
    val haptic = LocalHapticFeedback.current
    var holdJob by remember { mutableStateOf<Job?>(null) }
    val currentOnComplete by rememberUpdatedState(onHoldComplete)

    DisposableEffect(Unit) {
        onDispose {
            holdJob?.cancel()
            holdJob = null
        }
    }

    val cancelHold: () -> Unit = {
        holdJob?.cancel()
        holdJob = null
        scope.launch { progress.animateTo(0f, tween(Motion.fast, easing = Motion.EaseStandard)) }
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = Touch.MinTarget)
            .clip(RoundedCornerShape(Radius.M))
            .background(MaterialTheme.colorScheme.error)
            .semantics {
                role = Role.Button
                contentDescription = "长按 3 秒引爆物理自毁，不可恢复"
            }
            .pointerInput(holdMillis) {
                detectTapGestures(
                    onPress = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        holdJob = scope.launch {
                            progress.snapTo(0f)
                            progress.animateTo(
                                targetValue = 1f,
                                animationSpec = tween(durationMillis = holdMillis, easing = LinearEasing)
                            )
                            currentOnComplete()
                            progress.snapTo(0f)
                        }
                        tryAwaitRelease()
                        if (progress.value < 1f) cancelHold()
                    }
                )
            },
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .matchParentSize()
                .padding(Space.XXS)
                .clip(RoundedCornerShape(Radius.M))
                .background(MaterialTheme.colorScheme.onError.copy(alpha = 0.25f))
        ) {
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(progress.value)
                    .background(MaterialTheme.colorScheme.onError.copy(alpha = 0.45f))
            )
        }
        Text(
            text = if (progress.value > 0f && progress.value < 1f) {
                "继续按住…${(progress.value * 100).toInt()}%"
            } else {
                "长按 3 秒引爆物理自毁 (不可恢复)"
            },
            fontWeight = FontWeight.SemiBold,
            style = Type.BodyL,
            color = MaterialTheme.colorScheme.onError
        )
    }
}
