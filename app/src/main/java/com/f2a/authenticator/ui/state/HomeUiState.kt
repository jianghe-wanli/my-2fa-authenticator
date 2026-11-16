package com.f2a.authenticator.ui.state

import androidx.compose.runtime.Immutable
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.CollapsePolicy
import com.f2a.authenticator.data.model.SortMode
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.Workspace

@Immutable
data class IssuerGroupUi(
    val key: String,
    val issuer: String,
    val accounts: List<AuthToken>,
    val isExpanded: Boolean,
    val headerPeriod: Int,
    val isAllHotp: Boolean,
    val hasMixedPeriods: Boolean,
    val hasPinned: Boolean,
    val lastActivityAt: Long
)

@Immutable
data class TrashItemUi(
    val token: AuthToken,
    val deletedAt: Long,
    val expiresAt: Long,
    val remainingDays: Int
)

@Immutable
data class HomeUiState(
    val workspaces: List<Workspace> = emptyList(),
    val activeWorkspaceId: String = "all",
    val tags: List<Tag> = emptyList(),
    val selectedTagFilterId: String? = null,
    val isSearchExpanded: Boolean = false,
    val searchQuery: String = "",
    val isFiltering: Boolean = false,
    val sortMode: SortMode = SortMode.PINNED_AND_COUNT,
    val collapsePolicy: CollapsePolicy = CollapsePolicy.COLLAPSE_ALL,
    val issuerGroups: List<IssuerGroupUi> = emptyList(),
    val groupsByWorkspace: Map<String, List<IssuerGroupUi>> = emptyMap(),
    val allExpanded: Boolean = false,
    val clipboardClearSeconds: Int = 45,
    val isLoaded: Boolean = false
)
