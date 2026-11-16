package com.f2a.authenticator.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.AddCircleOutline
import androidx.compose.material.icons.filled.UnfoldLess
import androidx.compose.material.icons.filled.UnfoldMore
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.f2a.authenticator.data.model.SortMode
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.ui.state.IssuerGroupUi
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type

@Composable
fun TagFilterBar(
    tags: List<Tag>,
    selectedTagFilterId: String?,
    issuerGroups: List<IssuerGroupUi>,
    allExpanded: Boolean,
    isFiltering: Boolean = false,
    sortMode: SortMode,
    onSelectTag: (String?) -> Unit,
    onLongClickTag: (Tag) -> Unit,
    onAddTagClick: () -> Unit,
    onToggleExpandAll: () -> Unit,
    onSelectSortMode: (SortMode) -> Unit,
    onJumpToIssuer: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val haptic = LocalHapticFeedback.current
    var sortMenuExpanded by remember { mutableStateOf(false) }

    Column(modifier = modifier.fillMaxWidth()) {
        LazyRow(
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(horizontal = Space.L),
            horizontalArrangement = Arrangement.spacedBy(Space.S),
            verticalAlignment = Alignment.CenterVertically
        ) {
            item(key = "all_tags") {
                TagPill(
                    label = "全部标签",
                    selected = selectedTagFilterId == null,
                    tagColor = MaterialTheme.colorScheme.primary,
                    onClick = { onSelectTag(null) }
                )
            }

            items(tags, key = { it.id }) { tag ->
                val isSelected = selectedTagFilterId == tag.id
                val tagColor = remember(tag.colorHex) { parseHexColor(tag.colorHex) }
                TagPill(
                    label = tag.name,
                    selected = isSelected,
                    tagColor = tagColor,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onSelectTag(if (isSelected) null else tag.id)
                    },
                    onLongClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onLongClickTag(tag)
                    }
                )
            }

            item(key = "add_tag") {
                IconButton(
                    onClick = onAddTagClick,
                    modifier = Modifier.size(Touch.MinTarget)
                ) {
                    Icon(
                        imageVector = Icons.Default.AddCircleOutline,
                        contentDescription = "新建标签",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(IconSize.L)
                    )
                }
            }
        }

        if (issuerGroups.isNotEmpty()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = Space.L, vertical = Space.XS),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(Space.S)
            ) {
                // 一键全部展开/折叠（筛选态全部命中组自动展开，无需误操作持久化态）
                if (!isFiltering) {
                    CompactToolPill(
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onToggleExpandAll()
                        }
                    ) {
                        Icon(
                            imageVector = if (allExpanded) Icons.Default.UnfoldLess else Icons.Default.UnfoldMore,
                            contentDescription = if (allExpanded) "全部折叠" else "全部展开",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(IconSize.XS)
                        )
                        Spacer(modifier = Modifier.width(Space.XS))
                        Text(
                            text = if (allExpanded) "全部折叠" else "全部展开",
                            style = Type.Label,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                // 排序方式下拉
                Box {
                    CompactToolPill(onClick = { sortMenuExpanded = true }) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.Sort,
                            contentDescription = "切换排序方式",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(IconSize.XS)
                        )
                        Spacer(modifier = Modifier.width(Space.XS))
                        Text(
                            text = sortModeLabel(sortMode),
                            style = Type.Label,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    DropdownMenu(
                        expanded = sortMenuExpanded,
                        onDismissRequest = { sortMenuExpanded = false }
                    ) {
                        SortMode.entries.forEach { mode ->
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = sortModeLabel(mode),
                                        fontWeight = if (mode == sortMode) FontWeight.Bold else FontWeight.Normal,
                                        color = if (mode == sortMode) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                                    )
                                },
                                onClick = {
                                    sortMenuExpanded = false
                                    onSelectSortMode(mode)
                                }
                            )
                        }
                    }
                }

                // 横向平台快跳索引胶囊
                LazyRow(
                    modifier = Modifier.weight(1f),
                    horizontalArrangement = Arrangement.spacedBy(Space.HS),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    items(issuerGroups, key = { "jump_${it.key}" }) { group ->
                        Box(
                            modifier = Modifier
                                .heightIn(min = Touch.CompactChipHeight)
                                .clip(RoundedCornerShape(Radius.M))
                                .background(
                                    if (group.isExpanded) {
                                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f)
                                    } else {
                                        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
                                    }
                                )
                                .clickable {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onJumpToIssuer(group.key)
                                }
                                .padding(horizontal = Space.MS, vertical = Space.HS),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "${group.issuer} (${group.accounts.size})",
                                style = Type.Caption,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                color = if (group.isExpanded) {
                                    MaterialTheme.colorScheme.onPrimaryContainer
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CompactToolPill(
    onClick: () -> Unit,
    content: @Composable () -> Unit
) {
    Row(
        modifier = Modifier
            .heightIn(min = Touch.CompactChipHeight)
            .clip(RoundedCornerShape(Radius.M))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f))
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.6f),
                shape = RoundedCornerShape(Radius.M)
            )
            .clickable(onClick = onClick)
            .padding(horizontal = Space.MS, vertical = Space.HS),
        verticalAlignment = Alignment.CenterVertically
    ) {
        content()
    }
}

private fun sortModeLabel(mode: SortMode): String = when (mode) {
    SortMode.PINNED_AND_COUNT -> "置顶+数量"
    SortMode.ALPHABETICAL_AZ -> "名称 A-Z"
    SortMode.RECENTLY_USED -> "最近使用"
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun TagPill(
    label: String,
    selected: Boolean,
    tagColor: Color,
    onClick: () -> Unit,
    onLongClick: (() -> Unit)? = null
) {
    val shape = RoundedCornerShape(Radius.M)
    val bgColor = if (selected) tagColor.copy(alpha = 0.18f) else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
    val borderColor = if (selected) tagColor.copy(alpha = 0.7f) else MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.6f)
    Box(
        modifier = Modifier
            .heightIn(min = Touch.MinTarget)
            .clip(shape)
            .background(bgColor)
            .border(1.dp, borderColor, shape)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .padding(horizontal = Space.M, vertical = Space.S),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            style = Type.Label,
            fontWeight = if (selected) FontWeight.ExtraBold else FontWeight.SemiBold,
            color = if (selected) tagColor else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
