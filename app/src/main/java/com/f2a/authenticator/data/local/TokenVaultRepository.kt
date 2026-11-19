package com.f2a.authenticator.data.local

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.AutoLockTimeout
import com.f2a.authenticator.data.model.CollapsePolicy
import com.f2a.authenticator.data.model.SortMode
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.ThemeMode
import com.f2a.authenticator.data.model.VaultPreferences
import com.f2a.authenticator.data.model.Workspace
import kotlinx.coroutines.flow.StateFlow

interface TokenVaultRepository {
    val workspaces: StateFlow<List<Workspace>>
    val tags: StateFlow<List<Tag>>
    /** 仅包含未软删除（deletedAt == null）的活跃凭据 */
    val tokens: StateFlow<List<AuthToken>>
    /** 回收站中的软删除凭据（deletedAt != null） */
    val trashedTokens: StateFlow<List<AuthToken>>
    /** 是否已完成解锁解密加载 */
    val isLoaded: StateFlow<Boolean>
    /** 是否已被胁迫/自毁清空（供进入空库伪装态时结束加载指示） */
    val isWiped: StateFlow<Boolean>
    /** 主备数据文件均损坏且无法解析时置为 true（只读保护，禁止空库覆写磁盘） */
    val vaultLoadCorrupted: StateFlow<Boolean>

    /** 仅检测磁盘是否存在已保存密文，不触发 KeyStore 解密（供未解锁时检测 PIN 被删篡改） */
    fun hasStoredEncryptedTokens(): Boolean

    /** 解锁成功后在 Dispatchers.IO 下解密并加载全库，预热 encCache 并清理超 7 天回收站 */
    suspend fun unlockAndLoad()

    /** 后台锁定时清空内存明文与 encCache，不删除磁盘密文 */
    fun lockInMemory()

    /** 非阻塞同步阻断后续写盘并清空内存明文（供自毁前同步回调使用） */
    fun wipeInMemoryImmediate() {}

    /** 胁迫触发或自毁时立即同步清空内存 StateFlow 与 encCache，并永久禁止后续写盘 */
    suspend fun wipeInMemoryState()

    suspend fun addToken(token: AuthToken)
    suspend fun addTokens(tokens: List<AuthToken>)
    /** 返回 Pair(新增条数, 跳过重复条数)，按 id 与 (workspaceId, issuer, accountName) 去重 */
    suspend fun addTokensDedup(tokens: List<AuthToken>): Pair<Int, Int>
    suspend fun updateToken(token: AuthToken)
    suspend fun advanceHotp(tokenId: String)
    suspend fun togglePin(tokenId: String)
    suspend fun recordTokenUsed(tokenId: String)

    /** 7 天软删除回收站 */
    suspend fun softDeleteToken(id: String)
    suspend fun restoreToken(id: String)
    suspend fun permanentlyDeleteToken(id: String)
    suspend fun emptyTrash()
    suspend fun purgeExpiredTrash(retentionMillis: Long = 7L * 24 * 60 * 60 * 1000)
    suspend fun clearAllTokens()

    suspend fun addTag(tag: Tag)
    suspend fun addTagIfAbsent(tag: Tag)
    suspend fun deleteTag(tagId: String)

    suspend fun addWorkspace(workspace: Workspace)
    suspend fun addWorkspaceIfAbsent(workspace: Workspace)
    suspend fun renameWorkspace(workspaceId: String, newName: String)
    suspend fun updateWorkspacesOrder(orderedIds: List<String>)
    suspend fun deleteWorkspace(workspaceId: String)

    /** 供测试与自毁释放协程作用域 */
    fun close()
}

interface VaultPreferencesRepository {
    val preferences: StateFlow<VaultPreferences>

    fun setCollapsePolicy(policy: CollapsePolicy)
    fun setSortMode(mode: SortMode)
    fun setThemeMode(mode: ThemeMode)
    fun setAutoLockTimeout(timeout: AutoLockTimeout)
    fun setLastActiveWorkspaceId(workspaceId: String)
    fun setPrivacyMaskEnabled(enabled: Boolean)
    fun recordBackupCompleted(timestampMs: Long, tokenCount: Int)

    /** 按 workspaceId 隔离读取/更新某工作区下的展开分组 key 集合 */
    fun setGroupExpanded(workspaceId: String, issuerKey: String, expanded: Boolean)
    fun setWorkspaceExpandedKeys(workspaceId: String, issuerKeys: Set<String>)
    fun clearAllPreferences()
}
