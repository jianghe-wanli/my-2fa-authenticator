package com.f2a.authenticator.ui.screens.home

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SearchOff
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.unit.dp
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.ui.components.CopyFeedback
import com.f2a.authenticator.ui.components.EmptyState
import com.f2a.authenticator.ui.components.IssuerAccordionCard
import com.f2a.authenticator.ui.components.TagFilterBar
import com.f2a.authenticator.ui.components.WorkspaceTabBar
import com.f2a.authenticator.ui.state.HomeUiState
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainHomeScreen(
    uiState: HomeUiState,
    nowMsProvider: () -> Long,
    onSelectWorkspace: (String) -> Unit,
    onSetSearchExpanded: (Boolean) -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onSelectTagFilter: (String?) -> Unit,
    onClearFilters: () -> Unit,
    onToggleExpandGroup: (String) -> Unit,
    onToggleExpandAll: () -> Unit,
    onSelectSortMode: (com.f2a.authenticator.data.model.SortMode) -> Unit,
    onJumpToIssuer: (String) -> Int,
    onTogglePin: (String) -> Unit,
    onSoftDeleteToken: (String) -> Unit,
    onAdvanceHotp: (AuthToken) -> Unit,
    onRecordTokenUsed: (String) -> Unit,
    onAddTag: (name: String, colorHex: String) -> Unit,
    onDeleteTag: (String) -> Unit,
    onOpenAddDialog: () -> Unit,
    onOpenScanScreen: () -> Unit,
    onOpenSettingsScreen: () -> Unit,
    onLockNow: () -> Unit,
    onTokenClick: (AuthToken) -> Unit,
    importNotice: String?,
    onImportNoticeShown: () -> Unit
) {
    val haptic = LocalHapticFeedback.current
    val snackbarHostState = remember { SnackbarHostState() }
    val uiScope = rememberCoroutineScope()
    val searchFocusRequester = remember { FocusRequester() }

    var showCreateTagDialog by remember { mutableStateOf(false) }
    var tagToDelete by remember { mutableStateOf<Tag?>(null) }
    var tokenToDelete by remember { mutableStateOf<AuthToken?>(null) }

    BackHandler(enabled = uiState.isSearchExpanded) {
        onSetSearchExpanded(false)
    }

    LaunchedEffect(uiState.isSearchExpanded) {
        if (uiState.isSearchExpanded) {
            delay(60L)
            searchFocusRequester.requestFocus()
        }
    }

    LaunchedEffect(importNotice) {
        if (!importNotice.isNullOrBlank()) {
            snackbarHostState.currentSnackbarData?.dismiss()
            snackbarHostState.showSnackbar(importNotice)
            onImportNoticeShown()
        }
    }

    val workspaceList = remember(uiState.workspaces) {
        listOf(Workspace(id = "all", name = "全部", colorHex = "#6366F1")) + uiState.workspaces
    }
    val initialPage = remember(workspaceList, uiState.activeWorkspaceId) {
        workspaceList.indexOfFirst { it.id == uiState.activeWorkspaceId }.coerceAtLeast(0)
    }
    val pagerState = rememberPagerState(initialPage = initialPage, pageCount = { workspaceList.size })
    val listStates = remember { mutableMapOf<String, LazyListState>() }
    var pendingScrollTarget by remember { mutableStateOf<Int?>(null) }

    LaunchedEffect(uiState.activeWorkspaceId, workspaceList, pagerState.settledPage) {
        if (uiState.workspaces.isEmpty()) return@LaunchedEffect
        val targetIndex = workspaceList.indexOfFirst { it.id == uiState.activeWorkspaceId }
        if (pendingScrollTarget == pagerState.settledPage) {
            pendingScrollTarget = null
        }
        if (targetIndex >= 0 &&
            pendingScrollTarget == null &&
            targetIndex != pagerState.currentPage &&
            !pagerState.isScrollInProgress
        ) {
            pagerState.scrollToPage(targetIndex)
        }
    }

    LaunchedEffect(pagerState, workspaceList, uiState.workspaces.isEmpty()) {
        if (uiState.workspaces.isEmpty()) return@LaunchedEffect
        snapshotFlow { pagerState.settledPage }
            .distinctUntilChanged()
            .collect { page ->
                workspaceList.getOrNull(page)?.id?.let(onSelectWorkspace)
            }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    if (uiState.isSearchExpanded) {
                        OutlinedTextField(
                            value = uiState.searchQuery,
                            onValueChange = onSearchQueryChange,
                            placeholder = { Text("搜索平台、账号、环境或标签...") },
                            singleLine = true,
                            modifier = Modifier
                                .fillMaxWidth()
                                .focusRequester(searchFocusRequester),
                            trailingIcon = {
                                IconButton(
                                    onClick = { onSetSearchExpanded(false) },
                                    modifier = Modifier.size(Touch.MinTarget)
                                ) {
                                    Icon(Icons.Default.Close, contentDescription = "关闭搜索", modifier = Modifier.size(IconSize.M))
                                }
                            }
                        )
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(34.dp)
                                    .clip(RoundedCornerShape(Radius.S))
                                    .background(MaterialTheme.colorScheme.primaryContainer),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Shield,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(IconSize.M)
                                )
                            }
                            Spacer(modifier = Modifier.width(Space.MS))
                            Text(text = "极盾 2FA", style = Type.TitlePage)
                        }
                    }
                },
                actions = {
                    if (!uiState.isSearchExpanded) {
                        IconButton(onClick = { onSetSearchExpanded(true) }, modifier = Modifier.size(Touch.MinTarget)) {
                            Icon(Icons.Default.Search, contentDescription = "搜索", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(IconSize.L))
                        }
                        IconButton(onClick = onOpenAddDialog, modifier = Modifier.size(Touch.MinTarget)) {
                            Icon(Icons.Default.Add, contentDescription = "添加凭据", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(IconSize.L))
                        }
                        IconButton(onClick = onLockNow, modifier = Modifier.size(Touch.MinTarget)) {
                            Icon(Icons.Default.Lock, contentDescription = "立即锁定", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(IconSize.M))
                        }
                        IconButton(onClick = onOpenSettingsScreen, modifier = Modifier.size(Touch.MinTarget)) {
                            Icon(Icons.Default.Settings, contentDescription = "设置", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(IconSize.L))
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background)
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onOpenScanScreen()
                },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                shape = CircleShape
            ) {
                Icon(Icons.Default.QrCodeScanner, contentDescription = "扫码添加", modifier = Modifier.size(IconSize.XL))
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            WorkspaceTabBar(
                workspaces = workspaceList,
                selectedIndex = pagerState.currentPage,
                onSelectWorkspace = { index, ws ->
                    pendingScrollTarget = index
                    onSelectWorkspace(ws.id)
                    uiScope.launch {
                        try {
                            pagerState.animateScrollToPage(index)
                        } finally {
                            if (pendingScrollTarget == index) {
                                pendingScrollTarget = null
                            }
                        }
                    }
                }
            )

            TagFilterBar(
                tags = uiState.tags,
                selectedTagFilterId = uiState.selectedTagFilterId,
                issuerGroups = uiState.issuerGroups,
                allExpanded = uiState.allExpanded,
                isFiltering = uiState.isFiltering,
                sortMode = uiState.sortMode,
                onSelectTag = onSelectTagFilter,
                onLongClickTag = { tag -> tagToDelete = tag },
                onAddTagClick = { showCreateTagDialog = true },
                onToggleExpandAll = onToggleExpandAll,
                onSelectSortMode = onSelectSortMode,
                onJumpToIssuer = { key ->
                    val idx = onJumpToIssuer(key)
                    if (idx >= 0) {
                        val activeListState = listStates[uiState.activeWorkspaceId]
                        if (activeListState != null) {
                            uiScope.launch { activeListState.animateScrollToItem(idx) }
                        }
                    }
                }
            )

            Spacer(modifier = Modifier.height(Space.XXS))

            HorizontalPager(
                state = pagerState,
                modifier = Modifier.fillMaxSize()
            ) { page ->
                val pageWorkspace = workspaceList.getOrNull(page) ?: return@HorizontalPager
                val pageListState = remember(pageWorkspace.id) {
                    listStates.getOrPut(pageWorkspace.id) { LazyListState() }
                }
                val pageGroups = uiState.groupsByWorkspace[pageWorkspace.id] ?: uiState.issuerGroups

                if (pageGroups.isEmpty()) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        EmptyState(
                            icon = if (uiState.isFiltering) Icons.Default.SearchOff else Icons.Default.Shield,
                            title = if (uiState.isFiltering) "未找到匹配凭据" else "当前工作区暂无凭据",
                            description = if (uiState.isFiltering) {
                                "换个关键词，或清除当前筛选条件"
                            } else {
                                "点击右下角扫码按钮，添加你的第一个 2FA 凭据"
                            },
                            primaryActionText = if (uiState.isFiltering) null else "扫码添加",
                            onPrimaryAction = if (uiState.isFiltering) null else onOpenScanScreen,
                            secondaryActionText = if (uiState.isFiltering) "清除筛选" else null,
                            onSecondaryAction = if (uiState.isFiltering) onClearFilters else null
                        )
                    }
                } else {
                    LazyColumn(
                        state = pageListState,
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(top = Space.XS, bottom = Space.BottomListPad)
                    ) {
                        items(pageGroups, key = { "${pageWorkspace.id}_${it.key}" }) { group ->
                            IssuerAccordionCard(
                                group = group,
                                allTags = uiState.tags,
                                clipboardClearSeconds = uiState.clipboardClearSeconds,
                                nowMsProvider = nowMsProvider,
                                onToggleExpand = { onToggleExpandGroup(group.key) },
                                onAccountClick = onTokenClick,
                                onTogglePin = onTogglePin,
                                onRequestDelete = { token -> tokenToDelete = token },
                                onAdvanceHotp = onAdvanceHotp,
                                onCopied = { tokenId ->
                                    onRecordTokenUsed(tokenId)
                                    CopyFeedback.show(snackbarHostState, uiScope, uiState.clipboardClearSeconds)
                                }
                            )
                        }
                    }
                }
            }
        }
    }

    tagToDelete?.let { target ->
        DeleteTagConfirmDialog(
            tag = target,
            onDismiss = { tagToDelete = null },
            onConfirm = {
                onDeleteTag(target.id)
                tagToDelete = null
                uiScope.launch { snackbarHostState.showSnackbar("标签已删除") }
            }
        )
    }

    if (showCreateTagDialog) {
        CreateTagDialog(
            onDismiss = { showCreateTagDialog = false },
            onCreate = { name, hex ->
                onAddTag(name, hex)
                showCreateTagDialog = false
                uiScope.launch { snackbarHostState.showSnackbar("标签创建成功") }
            }
        )
    }

    tokenToDelete?.let { target ->
        SoftDeleteTokenConfirmDialog(
            token = target,
            onDismiss = { tokenToDelete = null },
            onConfirm = {
                onSoftDeleteToken(target.id)
                tokenToDelete = null
                uiScope.launch { snackbarHostState.showSnackbar("已移入回收站（7 天内可恢复）") }
            }
        )
    }
}
