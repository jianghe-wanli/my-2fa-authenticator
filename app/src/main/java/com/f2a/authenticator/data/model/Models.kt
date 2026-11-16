package com.f2a.authenticator.data.model

import com.google.gson.annotations.SerializedName
import java.util.Locale
import java.util.UUID

const val CURRENT_VAULT_SCHEMA_VERSION = 2

/**
 * 顶级工作区实体
 */
data class Workspace(
    @SerializedName("id") val id: String = UUID.randomUUID().toString(),
    @SerializedName("name") val name: String = "未命名工作区",
    @SerializedName("iconName") val iconName: String = "Folder",
    @SerializedName("colorHex") val colorHex: String = "#3B82F6",
    @SerializedName("orderIndex") val orderIndex: Int = 0,
    @SerializedName("isBiometricProtected") val isBiometricProtected: Boolean = false
) {
    fun normalize(): Workspace {
        @Suppress("USELESS_ELVIS")
        val safeId = (id ?: "").ifBlank { UUID.randomUUID().toString() }
        @Suppress("USELESS_ELVIS")
        val safeName = (name ?: "").ifBlank { "未命名工作区" }
        @Suppress("USELESS_ELVIS")
        val safeIcon = (iconName ?: "").ifBlank { "Folder" }
        @Suppress("USELESS_ELVIS")
        val safeColor = (colorHex ?: "").ifBlank { "#3B82F6" }
        return copy(id = safeId, name = safeName, iconName = safeIcon, colorHex = safeColor)
    }

    companion object {
        val DEFAULT_PERSONAL = Workspace("workspace_personal", "个人生活", "Person", "#3B82F6", 0)
        val DEFAULT_WORK = Workspace("workspace_work", "工作主业", "BusinessCenter", "#10B981", 1)
        val DEFAULT_DEVOPS = Workspace("workspace_devops", "运维多租户", "Terminal", "#F59E0B", 2)
    }
}

/**
 * 动态标签定义（解决主要账号、小号、资产号等精细维度）
 */
data class Tag(
    @SerializedName("id") val id: String = UUID.randomUUID().toString(),
    @SerializedName("name") val name: String = "标签",
    @SerializedName("colorHex") val colorHex: String = "#6366F1",
    @SerializedName("isSystemDefault") val isSystemDefault: Boolean = false
) {
    fun normalize(): Tag {
        @Suppress("USELESS_ELVIS")
        val safeId = (id ?: "").ifBlank { UUID.randomUUID().toString() }
        @Suppress("USELESS_ELVIS")
        val safeName = (name ?: "").ifBlank { "标签" }
        @Suppress("USELESS_ELVIS")
        val safeColor = (colorHex ?: "").ifBlank { "#6366F1" }
        return copy(id = safeId, name = safeName, colorHex = safeColor)
    }

    companion object {
        val TAG_MAIN = Tag("tag_main", "👑 主要账号", "#3B82F6", true)
        val TAG_SUB = Tag("tag_sub", "🍼 辅助小号", "#10B981", true)
        val TAG_ASSET = Tag("tag_asset", "💰 核心资产", "#F59E0B", true)
        val TAG_DEV = Tag("tag_dev", "🛠️ 测试开发", "#8B5CF6", true)
    }
}

enum class TokenType {
    TOTP,
    HOTP,
    STEAM
}

/**
 * TOTP/HOTP/Steam 核心凭据条目
 */
data class AuthToken(
    @SerializedName("id") val id: String = UUID.randomUUID().toString(),
    @SerializedName("workspaceId") val workspaceId: String = Workspace.DEFAULT_PERSONAL.id,
    @SerializedName("issuer") val issuer: String = "未知平台",
    @SerializedName("accountName") val accountName: String = "默认账号",
    @SerializedName("tenantEnv") val tenantEnv: String = "",
    @SerializedName("secret") val secret: String = "",
    @SerializedName("algorithm") val algorithm: String = "SHA1",
    @SerializedName("digits") val digits: Int = 6,
    @SerializedName("period") val period: Int = 30,
    @SerializedName("counter") val counter: Long = 0L,
    @SerializedName("type") val type: TokenType = TokenType.TOTP,
    @SerializedName("tagIds") val tagIds: List<String> = emptyList(),
    @SerializedName("note") val note: String = "",
    @SerializedName("isPinned") val isPinned: Boolean = false,
    @SerializedName("createdAt") val createdAt: Long = System.currentTimeMillis(),
    @SerializedName("updatedAt") val updatedAt: Long = System.currentTimeMillis(),
    @SerializedName("secretInvalid") val secretInvalid: Boolean = false,
    @SerializedName("deletedAt") val deletedAt: Long? = null,
    @SerializedName("lastUsedAt") val lastUsedAt: Long = 0L,
    @SerializedName("sortOrder") val sortOrder: Int = 0,
    @SerializedName("schemaVersion") val schemaVersion: Int = CURRENT_VAULT_SCHEMA_VERSION
) {
    /**
     * 清洗 Gson 绕过 Kotlin 默认值导致的潜在 null 字段，并完成 v1 -> v2 schema 迁移。
     */
    @Suppress("USELESS_ELVIS")
    fun normalize(fallbackWorkspaceId: String = Workspace.DEFAULT_PERSONAL.id): AuthToken {
        val safeType = type ?: TokenType.TOTP
        val safeDigits = when (safeType) {
            TokenType.STEAM -> 5
            else -> if (digits == 8) 8 else 6
        }
        val safePeriod = if (period in 15..120) period else 30
        val safeAlgo = when ((algorithm ?: "SHA1").trim().uppercase(Locale.US)) {
            "SHA256", "SHA-256", "HMACSHA256" -> "SHA256"
            "SHA512", "SHA-512", "HMACSHA512" -> "SHA512"
            else -> "SHA1"
        }
        return copy(
            id = (id ?: "").ifBlank { UUID.randomUUID().toString() },
            workspaceId = (workspaceId ?: "").ifBlank { fallbackWorkspaceId },
            issuer = (issuer ?: "").ifBlank { "未知平台" },
            accountName = (accountName ?: "").ifBlank { "默认账号" },
            tenantEnv = tenantEnv ?: "",
            secret = secret ?: "",
            algorithm = safeAlgo,
            digits = safeDigits,
            period = safePeriod,
            counter = counter.coerceAtLeast(0L),
            type = safeType,
            tagIds = (tagIds ?: emptyList()).filterNotNull(),
            note = note ?: "",
            schemaVersion = CURRENT_VAULT_SCHEMA_VERSION
        )
    }
}

data class IssuerGroup(
    val issuer: String,
    val accounts: List<AuthToken>,
    val isExpanded: Boolean = false, // V2 默认全部折叠
    val key: String = issuer.trim().lowercase(Locale.US)
)

data class BackupPayload(
    @SerializedName("version") val version: Int = 2,
    @SerializedName("schemaVersion") val schemaVersion: Int = CURRENT_VAULT_SCHEMA_VERSION,
    @SerializedName("timestamp") val timestamp: Long = System.currentTimeMillis(),
    @SerializedName("workspaces") val workspaces: List<Workspace> = emptyList(),
    @SerializedName("tags") val tags: List<Tag> = emptyList(),
    @SerializedName("tokens") val tokens: List<AuthToken> = emptyList()
)

enum class CollapsePolicy {
    COLLAPSE_ALL,    // 默认全折叠（推荐）
    EXPAND_PINNED,   // 仅展开含置顶账号的分类
    REMEMBER_LAST    // 记忆上次按工作区展开的状态
}

enum class SortMode {
    PINNED_AND_COUNT, // 置顶优先 + 账号数降序
    ALPHABETICAL_AZ,  // 发行方 A-Z 字母序
    RECENTLY_USED     // 最近使用/更新优先
}

enum class ThemeMode {
    SYSTEM,
    DARK,
    LIGHT
}

enum class AutoLockTimeout(val seconds: Long) {
    IMMEDIATE(0L),
    SECONDS_30(30L),
    SECONDS_60(60L),
    SECONDS_300(300L),
    NEVER(-1L)
}

data class VaultPreferences(
    @SerializedName("collapsePolicy") val collapsePolicy: CollapsePolicy = CollapsePolicy.COLLAPSE_ALL,
    @SerializedName("sortMode") val sortMode: SortMode = SortMode.PINNED_AND_COUNT,
    @SerializedName("themeMode") val themeMode: ThemeMode = ThemeMode.SYSTEM,
    @SerializedName("autoLockTimeout") val autoLockTimeout: AutoLockTimeout = AutoLockTimeout.SECONDS_30,
    @SerializedName("expandedIssuerKeys") val expandedIssuerKeys: Map<String, Set<String>> = emptyMap(),
    @SerializedName("lastActiveWorkspaceId") val lastActiveWorkspaceId: String = "all"
)
