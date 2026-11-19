package com.f2a.authenticator.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.f2a.authenticator.data.local.TokenVaultRepository
import com.f2a.authenticator.data.local.VaultPreferencesRepository
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.CollapsePolicy
import com.f2a.authenticator.data.model.SortMode
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.data.model.VaultPreferences
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.Clock
import com.f2a.authenticator.security.SecurityLockManager
import com.f2a.authenticator.security.SystemClockImpl
import com.f2a.authenticator.ui.state.HomeUiState
import com.f2a.authenticator.ui.state.IssuerGroupUi
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.Locale

class HomeViewModel(
    private val tokenRepository: TokenVaultRepository,
    private val preferencesRepository: VaultPreferencesRepository,
    private val securityManager: SecurityLockManager,
    private val clock: Clock = SystemClockImpl,
    computeDispatcher: CoroutineDispatcher = Dispatchers.Default
) : ViewModel() {

    private val activeWorkspaceIdFlow = MutableStateFlow(
        preferencesRepository.preferences.value.lastActiveWorkspaceId.ifBlank { "all" }
    )
    private val selectedTagFilterIdFlow = MutableStateFlow<String?>(null)
    private val isSearchExpandedFlow = MutableStateFlow(false)
    private val searchQueryFlow = MutableStateFlow("")

    // 会话级折叠状态表（用于 COLLAPSE_ALL / EXPAND_PINNED 策略，防止污染持久化偏好）
    private val sessionExpandedByWsFlow = MutableStateFlow<Map<String, Set<String>>>(emptyMap())
    private val clipboardClearSecondsFlow = MutableStateFlow(securityManager.getClipboardClearSeconds())

    val uiState: StateFlow<HomeUiState> = combine(
        tokenRepository.workspaces,
        tokenRepository.tags,
        tokenRepository.tokens,
        tokenRepository.isLoaded,
        tokenRepository.isWiped,
        tokenRepository.vaultLoadCorrupted,
        preferencesRepository.preferences,
        activeWorkspaceIdFlow,
        selectedTagFilterIdFlow,
        isSearchExpandedFlow,
        searchQueryFlow,
        sessionExpandedByWsFlow,
        clipboardClearSecondsFlow
    ) { values ->
        @Suppress("UNCHECKED_CAST")
        val workspaces = values[0] as List<Workspace>
        @Suppress("UNCHECKED_CAST")
        val tags = values[1] as List<Tag>
        @Suppress("UNCHECKED_CAST")
        val tokens = values[2] as List<AuthToken>
        val isLoaded = values[3] as Boolean
        val isWiped = values[4] as Boolean
        val vaultLoadCorrupted = values[5] as Boolean
        val prefs = values[6] as VaultPreferences
        val activeWsId = values[7] as String
        val selectedTagId = values[8] as String?
        val searchExpanded = values[9] as Boolean
        val query = values[10] as String
        @Suppress("UNCHECKED_CAST")
        val sessionExpandedMap = values[11] as Map<String, Set<String>>
        val clipSec = values[12] as Int

        val isFiltering = query.isNotBlank() || selectedTagId != null
        val tagMap = tags.associateBy { it.id }
        val trimmedQuery = query.trim()

        // 若当前工作区已被删除（且工作区已加载完成），自动回退到 "all"
        val resolvedActiveWsId = if (activeWsId != "all" && workspaces.isNotEmpty() && workspaces.none { it.id == activeWsId }) {
            "all"
        } else {
            activeWsId
        }

        val buildGroupsForWs: (String) -> List<IssuerGroupUi> = { targetWsId ->
            val filtered = tokens.filter { token ->
                val matchesWs = targetWsId == "all" || token.workspaceId == targetWsId
                val matchesTag = selectedTagId == null || token.tagIds.contains(selectedTagId)
                val matchesQuery = if (trimmedQuery.isEmpty()) {
                    true
                } else {
                    token.issuer.contains(trimmedQuery, ignoreCase = true) ||
                        token.accountName.contains(trimmedQuery, ignoreCase = true) ||
                        token.tenantEnv.contains(trimmedQuery, ignoreCase = true) ||
                        token.note.contains(trimmedQuery, ignoreCase = true) ||
                        token.tagIds.any { id -> tagMap[id]?.name?.contains(trimmedQuery, ignoreCase = true) == true }
                }
                matchesWs && matchesTag && matchesQuery
            }

            val rawGroups = filtered.groupBy { it.issuer.trim().lowercase(Locale.US) }
            rawGroups.map { (key, groupTokens) ->
                val displayIssuer = pickNormalizedIssuerName(groupTokens)
                val sortedAccounts = when (prefs.sortMode) {
                    SortMode.RECENTLY_USED -> groupTokens.sortedWith(
                        compareByDescending<AuthToken> { it.isPinned }
                            .thenByDescending { it.lastUsedAt }
                            .thenByDescending { it.usageCount }
                            .thenBy { it.sortOrder }
                            .thenBy { it.accountName.lowercase(Locale.US) }
                    )
                    else -> groupTokens.sortedWith(
                        compareByDescending<AuthToken> { it.isPinned }
                            .thenBy { it.sortOrder }
                            .thenBy { it.accountName.lowercase(Locale.US) }
                    )
                }
                val hasPinned = sortedAccounts.any { it.isPinned }
                val isAllHotp = sortedAccounts.all { it.type == TokenType.HOTP }
                val totpPeriods = sortedAccounts.filter { it.type != TokenType.HOTP }.map { it.period }.distinct()
                val hasMixedPeriods = totpPeriods.size > 1 || (totpPeriods.isNotEmpty() && sortedAccounts.any { it.type == TokenType.HOTP })
                val headerPeriod = totpPeriods.firstOrNull() ?: 30
                val lastActivity = sortedAccounts.maxOfOrNull { it.lastUsedAt } ?: 0L

                val isExpanded = if (isFiltering) {
                    true
                } else {
                    resolveExpandedState(
                        policy = prefs.collapsePolicy,
                        workspaceId = targetWsId,
                        groupKey = key,
                        hasPinned = hasPinned,
                        persistedByWs = prefs.expandedIssuerKeys,
                        sessionByWs = sessionExpandedMap
                    )
                }

                IssuerGroupUi(
                    key = key,
                    issuer = displayIssuer,
                    accounts = sortedAccounts,
                    isExpanded = isExpanded,
                    headerPeriod = headerPeriod,
                    isAllHotp = isAllHotp,
                    hasMixedPeriods = hasMixedPeriods,
                    hasPinned = hasPinned,
                    lastActivityAt = lastActivity
                )
            }.let { list ->
                when (prefs.sortMode) {
                    SortMode.PINNED_AND_COUNT -> list.sortedWith(
                        compareByDescending<IssuerGroupUi> { it.hasPinned }
                            .thenByDescending { it.accounts.size }
                            .thenBy { it.issuer.lowercase(Locale.US) }
                    )
                    SortMode.ALPHABETICAL_AZ -> list.sortedBy { it.issuer.lowercase(Locale.US) }
                    SortMode.RECENTLY_USED -> list.sortedWith(
                        compareByDescending<IssuerGroupUi> { it.lastActivityAt }
                            .thenByDescending { group -> group.accounts.maxOfOrNull { it.usageCount } ?: 0 }
                            .thenBy { it.issuer.lowercase(Locale.US) }
                    )
                }
            }
        }

        val workspaceIds = listOf("all") + workspaces.map { it.id }
        val groupsByWs = workspaceIds.associateWith { wsId -> buildGroupsForWs(wsId) }
        val groups = groupsByWs[resolvedActiveWsId] ?: buildGroupsForWs(resolvedActiveWsId)
        val allExpanded = groups.isNotEmpty() && groups.all { it.isExpanded }

        val nowMs = clock.currentTimeMillis()
        val lastBackupMs = prefs.lastBackupAtMillis
        val daysSinceBackup = if (lastBackupMs != null && lastBackupMs > 0L) {
            ((nowMs - lastBackupMs).coerceAtLeast(0L) / DAY_MILLIS).toInt()
        } else {
            null
        }
        val backupOverdue = isLoaded &&
            tokens.isNotEmpty() &&
            (lastBackupMs == null || (daysSinceBackup ?: 0) >= BACKUP_OVERDUE_DAYS)

        HomeUiState(
            workspaces = workspaces,
            activeWorkspaceId = resolvedActiveWsId,
            tags = tags,
            selectedTagFilterId = selectedTagId,
            isSearchExpanded = searchExpanded,
            searchQuery = query,
            isFiltering = isFiltering,
            sortMode = prefs.sortMode,
            collapsePolicy = prefs.collapsePolicy,
            issuerGroups = groups,
            groupsByWorkspace = groupsByWs,
            allExpanded = allExpanded,
            clipboardClearSeconds = clipSec,
            isLoaded = isLoaded || isWiped,
            privacyMaskEnabled = prefs.privacyMaskEnabled,
            backupOverdueBanner = backupOverdue,
            daysSinceLastBackup = daysSinceBackup,
            vaultLoadCorrupted = vaultLoadCorrupted
        )
    }
        .flowOn(computeDispatcher)
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000L),
            initialValue = HomeUiState(
                workspaces = tokenRepository.workspaces.value,
                activeWorkspaceId = preferencesRepository.preferences.value.lastActiveWorkspaceId.ifBlank { "all" },
                tags = tokenRepository.tags.value,
                sortMode = preferencesRepository.preferences.value.sortMode,
                collapsePolicy = preferencesRepository.preferences.value.collapsePolicy,
                clipboardClearSeconds = securityManager.getClipboardClearSeconds(),
                isLoaded = tokenRepository.isLoaded.value || tokenRepository.isWiped.value,
                privacyMaskEnabled = preferencesRepository.preferences.value.privacyMaskEnabled,
                vaultLoadCorrupted = tokenRepository.vaultLoadCorrupted.value
            )
        )

    private fun resolveExpandedState(
        policy: CollapsePolicy,
        workspaceId: String,
        groupKey: String,
        hasPinned: Boolean,
        persistedByWs: Map<String, Set<String>>,
        sessionByWs: Map<String, Set<String>>
    ): Boolean {
        return when (policy) {
            CollapsePolicy.REMEMBER_LAST -> {
                persistedByWs[workspaceId]?.contains(groupKey) == true
            }
            CollapsePolicy.EXPAND_PINNED -> {
                val sessionSet = sessionByWs[workspaceId]
                if (sessionSet != null) groupKey in sessionSet else hasPinned
            }
            CollapsePolicy.COLLAPSE_ALL -> {
                sessionByWs[workspaceId]?.contains(groupKey) == true
            }
        }
    }

    private fun pickNormalizedIssuerName(tokens: List<AuthToken>): String {
        val candidates = tokens.map { it.issuer.trim() }.filter { it.isNotEmpty() }
        if (candidates.isEmpty()) return "未知平台"
        return candidates
            .groupingBy { it }
            .eachCount()
            .entries
            .sortedWith(
                compareByDescending<Map.Entry<String, Int>> { it.value }
                    .thenByDescending { entry -> entry.key.any { it.isUpperCase() } }
                    .thenBy { it.key }
            )
            .first()
            .key
    }

    fun refreshClipboardSeconds() {
        clipboardClearSecondsFlow.value = securityManager.getClipboardClearSeconds()
    }

    fun setActiveWorkspaceId(workspaceId: String) {
        if (activeWorkspaceIdFlow.value == workspaceId) return
        activeWorkspaceIdFlow.value = workspaceId
        preferencesRepository.setLastActiveWorkspaceId(workspaceId)
    }

    fun setSearchExpanded(expanded: Boolean) {
        isSearchExpandedFlow.value = expanded
        if (!expanded) {
            searchQueryFlow.value = ""
        }
    }

    fun setSearchQuery(query: String) {
        searchQueryFlow.value = query
    }

    fun clearSearch() {
        searchQueryFlow.value = ""
    }

    fun togglePrivacyMask() {
        val next = !preferencesRepository.preferences.value.privacyMaskEnabled
        preferencesRepository.setPrivacyMaskEnabled(next)
    }

    fun resetSessionUiState() {
        searchQueryFlow.value = ""
        isSearchExpandedFlow.value = false
        selectedTagFilterIdFlow.value = null
        sessionExpandedByWsFlow.value = emptyMap()
    }

    fun selectTagFilter(tagId: String?) {
        selectedTagFilterIdFlow.value = tagId
    }

    fun clearFilters() {
        searchQueryFlow.value = ""
        isSearchExpandedFlow.value = false
        selectedTagFilterIdFlow.value = null
    }

    fun setSortMode(mode: SortMode) {
        preferencesRepository.setSortMode(mode)
    }

    fun toggleGroupExpanded(groupKey: String) {
        val current = uiState.value
        if (current.isFiltering) return
        val wsId = current.activeWorkspaceId
        val targetGroup = current.issuerGroups.firstOrNull { it.key == groupKey } ?: return
        val newExpanded = !targetGroup.isExpanded

        val currentKeys = current.issuerGroups.filter { it.isExpanded }.map { it.key }.toMutableSet()
        if (newExpanded) currentKeys.add(groupKey) else currentKeys.remove(groupKey)

        sessionExpandedByWsFlow.update { it + (wsId to currentKeys) }
        preferencesRepository.setGroupExpanded(wsId, groupKey, newExpanded)
    }

    fun toggleExpandAll() {
        val current = uiState.value
        if (current.isFiltering) return
        val wsId = current.activeWorkspaceId
        val nextKeys = if (current.allExpanded) {
            emptySet()
        } else {
            current.issuerGroups.map { it.key }.toSet()
        }
        sessionExpandedByWsFlow.update { it + (wsId to nextKeys) }
        preferencesRepository.setWorkspaceExpandedKeys(wsId, nextKeys)
    }

    /**
     * 展开指定发行方并返回其在当前列表中的索引，供快跳胶囊滚动定位。
     */
    fun expandAndFindIndex(groupKey: String): Int {
        val current = uiState.value
        val wsId = current.activeWorkspaceId
        val idx = current.issuerGroups.indexOfFirst { it.key == groupKey }
        if (idx >= 0 && !current.isFiltering && !current.issuerGroups[idx].isExpanded) {
            val currentKeys = current.issuerGroups.filter { it.isExpanded }.map { it.key }.toMutableSet()
            currentKeys.add(groupKey)
            sessionExpandedByWsFlow.update { it + (wsId to currentKeys) }
            preferencesRepository.setGroupExpanded(wsId, groupKey, true)
        }
        return idx
    }

    fun togglePin(tokenId: String) {
        viewModelScope.launch {
            tokenRepository.togglePin(tokenId)
        }
    }

    fun softDeleteToken(tokenId: String) {
        viewModelScope.launch {
            tokenRepository.softDeleteToken(tokenId)
        }
    }

    fun advanceHotp(token: AuthToken) {
        viewModelScope.launch {
            tokenRepository.advanceHotp(token.id)
        }
    }

    fun recordTokenUsed(tokenId: String) {
        viewModelScope.launch {
            tokenRepository.recordTokenUsed(tokenId)
        }
    }

    fun addTag(name: String, colorHex: String) {
        viewModelScope.launch {
            tokenRepository.addTag(Tag(name = name.trim(), colorHex = colorHex))
        }
    }

    fun deleteTag(tagId: String) {
        viewModelScope.launch {
            if (selectedTagFilterIdFlow.value == tagId) {
                selectedTagFilterIdFlow.value = null
            }
            tokenRepository.deleteTag(tagId)
        }
    }

    class Factory(
        private val tokenRepository: TokenVaultRepository,
        private val preferencesRepository: VaultPreferencesRepository,
        private val securityManager: SecurityLockManager,
        private val clock: Clock = SystemClockImpl
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return HomeViewModel(tokenRepository, preferencesRepository, securityManager, clock) as T
        }
    }

    private companion object {
        const val DAY_MILLIS = 24L * 60 * 60 * 1000
        const val BACKUP_OVERDUE_DAYS = 30
    }
}
