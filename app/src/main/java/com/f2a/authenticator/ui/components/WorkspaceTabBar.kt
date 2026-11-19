package com.f2a.authenticator.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.Motion
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type

@Composable
fun WorkspaceTabBar(
    workspaces: List<Workspace>,
    selectedIndex: Int,
    onSelectWorkspace: (index: Int, workspace: Workspace) -> Unit,
    modifier: Modifier = Modifier
) {
    val haptic = LocalHapticFeedback.current
    val semantic = LocalSemanticColors.current
    val listState = rememberLazyListState()

    LaunchedEffect(selectedIndex, workspaces.size) {
        if (selectedIndex in workspaces.indices) {
            listState.animateScrollToItem(selectedIndex)
        }
    }

    LazyRow(
        state = listState,
        modifier = modifier.fillMaxWidth(),
        contentPadding = PaddingValues(horizontal = Space.L, vertical = Space.S),
        horizontalArrangement = Arrangement.spacedBy(Space.S),
        verticalAlignment = Alignment.CenterVertically
    ) {
        itemsIndexed(
            items = workspaces,
            key = { _, ws -> ws.id },
            contentType = { _, _ -> "workspace_tab" }
        ) { index, ws ->
            val isSelected = selectedIndex == index
            val wsColor = remember(ws.colorHex) { parseHexColor(ws.colorHex) }
            val bgColor by animateColorAsState(
                targetValue = if (isSelected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent,
                animationSpec = tween(durationMillis = Motion.base),
                label = "ws_tab_bg"
            )
            val borderColor by animateColorAsState(
                targetValue = if (isSelected) {
                    MaterialTheme.colorScheme.primary.copy(alpha = 0.45f)
                } else {
                    semantic.borderSubtle.copy(alpha = 0.5f)
                },
                animationSpec = tween(durationMillis = Motion.base),
                label = "ws_tab_border"
            )

            Column(
                modifier = Modifier
                    .heightIn(min = Touch.SegmentedHeight)
                    .clip(RoundedCornerShape(Radius.M))
                    .background(bgColor)
                    .border(
                        width = 1.dp,
                        color = borderColor,
                        shape = RoundedCornerShape(Radius.M)
                    )
                    .clickable {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onSelectWorkspace(index, ws)
                    }
                    .padding(horizontal = Space.ML, vertical = Space.HS),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (ws.id != "all") {
                        Box(
                            modifier = Modifier
                                .size(6.dp)
                                .clip(CircleShape)
                                .background(wsColor)
                        )
                        Spacer(modifier = Modifier.width(Space.HS))
                    }
                    Text(
                        text = ws.name,
                        style = Type.BodyM,
                        fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Medium,
                        color = if (isSelected) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                }
                if (isSelected) {
                    Spacer(modifier = Modifier.height(3.dp))
                    Box(
                        modifier = Modifier
                            .width(18.dp)
                            .height(2.dp)
                            .clip(RoundedCornerShape(Radius.Full))
                            .background(MaterialTheme.colorScheme.primary)
                    )
                }
            }
        }
    }
}
