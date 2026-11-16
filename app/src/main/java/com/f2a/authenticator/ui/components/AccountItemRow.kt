package com.f2a.authenticator.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.Motion
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type
import com.f2a.authenticator.utils.SecureClipboard
import kotlinx.coroutines.delay

@Composable
fun AccountItemRow(
    token: AuthToken,
    allTags: List<Tag>,
    clipboardClearSeconds: Int,
    nowMsProvider: () -> Long,
    onClick: () -> Unit,
    onTogglePin: () -> Unit,
    onRequestDelete: () -> Unit,
    onAdvanceHotp: () -> Unit,
    onCopied: () -> Unit
) {
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val semantic = LocalSemanticColors.current

    val envColors = remember(token.tenantEnv, semantic) { getEnvColors(token.tenantEnv, semantic) }
    var showNextCodePreview by rememberSaveable(token.id) { mutableStateOf(false) }
    var copiedFeedback by remember(token.id) { mutableStateOf(false) }
    var menuExpanded by remember(token.id) { mutableStateOf(false) }

    LaunchedEffect(copiedFeedback) {
        if (copiedFeedback) {
            delay(Motion.hold)
            copiedFeedback = false
        }
    }

    val matchedTagsWithColor = remember(token.tagIds, allTags) {
        allTags.filter { token.tagIds.contains(it.id) }
            .map { it to parseHexColor(it.colorHex) }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = Space.L, vertical = Space.M)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (token.isPinned) {
                Icon(
                    imageVector = Icons.Default.PushPin,
                    contentDescription = "已置顶",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(14.dp)
                )
                Spacer(modifier = Modifier.width(Space.XS))
            }

            val isDarkSurface = MaterialTheme.colorScheme.surface.luminance() < 0.5f
            matchedTagsWithColor.take(1).forEach { (tag, tagColor) ->
                val textColor = accessibleTagTextColor(tagColor, isDarkSurface)
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(Radius.XS))
                        .background(tagColor.copy(alpha = 0.16f))
                        .padding(horizontal = Space.HS, vertical = Space.XXS)
                ) {
                    Text(
                        text = tag.name,
                        color = textColor,
                        style = Type.Caption,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Spacer(modifier = Modifier.width(Space.HS))
            }
            if (matchedTagsWithColor.size > 1) {
                Text(
                    text = "+${matchedTagsWithColor.size - 1}",
                    style = Type.Caption,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.width(Space.HS))
            }

            if (token.tenantEnv.isNotBlank()) {
                val (badgeBg, badgeText) = envColors
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(Radius.XS))
                        .background(badgeBg)
                        .padding(horizontal = Space.HS, vertical = Space.XXS)
                ) {
                    Text(
                        text = token.tenantEnv,
                        color = badgeText,
                        style = Type.Label,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Spacer(modifier = Modifier.width(Space.S))
            }

            Text(
                text = token.accountName,
                style = Type.BodyM,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )

            if (token.type != TokenType.HOTP) {
                IconButton(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        showNextCodePreview = !showNextCodePreview
                    },
                    modifier = Modifier.size(Touch.MinTarget)
                ) {
                    Icon(
                        imageVector = Icons.Default.Visibility,
                        contentDescription = "预览下一周期验证码",
                        tint = if (showNextCodePreview) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.55f)
                        },
                        modifier = Modifier.size(IconSize.M)
                    )
                }
            }

            Box {
                IconButton(
                    onClick = { menuExpanded = true },
                    modifier = Modifier.size(Touch.MinTarget)
                ) {
                    Icon(
                        imageVector = Icons.Default.MoreVert,
                        contentDescription = "账号快捷操作",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(IconSize.M)
                    )
                }
                DropdownMenu(
                    expanded = menuExpanded,
                    onDismissRequest = { menuExpanded = false }
                ) {
                    DropdownMenuItem(
                        text = { Text(if (token.isPinned) "取消置顶" else "置顶该账号") },
                        leadingIcon = { Icon(Icons.Default.PushPin, contentDescription = null) },
                        onClick = {
                            menuExpanded = false
                            onTogglePin()
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("查看与编辑详情") },
                        leadingIcon = { Icon(Icons.Default.Edit, contentDescription = null) },
                        onClick = {
                            menuExpanded = false
                            onClick()
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("移入回收站", color = semantic.errorText) },
                        leadingIcon = {
                            Icon(Icons.Default.Delete, contentDescription = null, tint = semantic.errorText)
                        },
                        onClick = {
                            menuExpanded = false
                            onRequestDelete()
                        }
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(Space.XS))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OtpRowCodeDisplay(
                token = token,
                showNextCodePreview = showNextCodePreview,
                nowMsProvider = nowMsProvider,
                modifier = Modifier.weight(1f)
            )

            if (token.type == TokenType.HOTP && !token.secretInvalid) {
                FilledTonalButton(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onAdvanceHotp()
                    },
                    shape = RoundedCornerShape(Radius.M),
                    colors = ButtonDefaults.filledTonalButtonColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer
                    ),
                    contentPadding = PaddingValues(horizontal = Space.MS, vertical = Space.HS),
                    modifier = Modifier.heightIn(min = Touch.MinTarget)
                ) {
                    Text("下一个", style = Type.BodyS, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.width(Space.HS))
            }

            FilledTonalButton(
                onClick = {
                    if (token.secretInvalid) return@FilledTonalButton
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    val code = computeTokenOtpCode(
                        token = token,
                        cycleOffset = if (showNextCodePreview) 1 else 0,
                        nowMs = nowMsProvider()
                    )
                    SecureClipboard.copy(context, code, clipboardClearSeconds)
                    copiedFeedback = true
                    onCopied()
                },
                enabled = !token.secretInvalid,
                shape = RoundedCornerShape(Radius.M),
                colors = ButtonDefaults.filledTonalButtonColors(
                    containerColor = if (copiedFeedback) {
                        semantic.success.copy(alpha = 0.16f)
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    }
                ),
                contentPadding = PaddingValues(horizontal = Space.ML, vertical = Space.HS),
                modifier = Modifier.heightIn(min = Touch.MinTarget)
            ) {
                AnimatedContent(
                    targetState = copiedFeedback,
                    transitionSpec = {
                        fadeIn(tween(Motion.fast, easing = Motion.EaseStandard)) togetherWith
                            fadeOut(tween(Motion.fast, easing = Motion.EaseStandard))
                    },
                    label = "copy_anim"
                ) { isCopied ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (isCopied) Icons.Default.Check else Icons.Default.ContentCopy,
                            contentDescription = null,
                            tint = if (isCopied) semantic.success else MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.size(IconSize.S)
                        )
                        Spacer(modifier = Modifier.width(Space.XS))
                        Text(
                            text = if (isCopied) "已复制" else "复制",
                            style = Type.BodyS,
                            fontWeight = FontWeight.Bold,
                            color = if (isCopied) semantic.success else MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }

        if (token.note.isNotBlank()) {
            Spacer(modifier = Modifier.height(Space.XXS))
            Text(
                text = "备忘: ${token.note}",
                style = Type.Caption,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
