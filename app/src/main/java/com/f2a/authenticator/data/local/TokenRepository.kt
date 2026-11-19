package com.f2a.authenticator.data.local

import android.content.Context
import android.content.SharedPreferences
import com.f2a.authenticator.crypto.KeyStoreManager
import com.f2a.authenticator.crypto.SecretCipher
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.CURRENT_VAULT_SCHEMA_VERSION
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.Clock
import com.f2a.authenticator.security.SystemClockImpl
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

internal data class VaultDocument(
    @SerializedName("schemaVersion") val schemaVersion: Int = CURRENT_VAULT_SCHEMA_VERSION,
    @SerializedName("workspaces") val workspaces: List<Workspace> = emptyList(),
    @SerializedName("tags") val tags: List<Tag> = emptyList(),
    @SerializedName("tokens") val tokens: List<AuthToken> = emptyList()
)

internal data class LegacyVaultSections(
    val workspacesJson: String?,
    val tagsJson: String?,
    val tokensJson: String?
)

internal interface VaultDocumentStorage {
    fun readDocumentJson(): String?
    fun readBackupDocumentJson(): String? = null
    fun hasAnyDocumentFile(): Boolean = !readDocumentJson().isNullOrBlank()
    fun writeDocumentJson(json: String)
    fun hasLegacyTokens(): Boolean
    fun readLegacySections(): LegacyVaultSections?
    fun clearLegacy()
}

internal class FileVaultDocumentStorage(context: Context) : VaultDocumentStorage {
    private val appContext = context.applicationContext ?: context
    private val docFile = File(appContext.filesDir, DOC_FILE_NAME)
    private val bakFile = File(appContext.filesDir, "$DOC_FILE_NAME.bak")
    private val tmpFile = File(appContext.filesDir, "$DOC_FILE_NAME.tmp")
    private val legacyPrefs: SharedPreferences by lazy {
        appContext.getSharedPreferences(LEGACY_PREF_NAME, Context.MODE_PRIVATE)
    }

    override fun readDocumentJson(): String? {
        return try {
            if (!docFile.exists() || !docFile.isFile) null
            else docFile.readText(Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    override fun readBackupDocumentJson(): String? {
        return try {
            if (!bakFile.exists() || !bakFile.isFile) null
            else bakFile.readText(Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    override fun hasAnyDocumentFile(): Boolean {
        return (docFile.exists() && docFile.isFile && docFile.length() > 0L) ||
            (bakFile.exists() && bakFile.isFile && bakFile.length() > 0L)
    }

    override fun writeDocumentJson(json: String) {
        docFile.parentFile?.mkdirs()
        FileOutputStream(tmpFile).use { fos ->
            fos.write(json.toByteArray(Charsets.UTF_8))
            fos.flush()
            try {
                fos.fd.sync()
            } catch (_: Exception) {
            }
        }
        // 写入新主文件前先将当前有效主文件滚动备份至 .bak
        if (docFile.exists() && docFile.isFile && docFile.length() > 0L) {
            try {
                Files.copy(
                    docFile.toPath(),
                    bakFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING
                )
            } catch (_: Exception) {
            }
        }
        try {
            Files.move(
                tmpFile.toPath(),
                docFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(
                tmpFile.toPath(),
                docFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING
            )
        }
    }

    override fun hasLegacyTokens(): Boolean {
        return try {
            val raw = legacyPrefs.getString(LEGACY_KEY_TOKENS, null)
            !raw.isNullOrBlank() && raw.trim() != "[]"
        } catch (_: Exception) {
            false
        }
    }

    override fun readLegacySections(): LegacyVaultSections? {
        return try {
            val ws = legacyPrefs.getString(LEGACY_KEY_WORKSPACES, null)
            val tags = legacyPrefs.getString(LEGACY_KEY_TAGS, null)
            val tokens = legacyPrefs.getString(LEGACY_KEY_TOKENS, null)
            if (ws.isNullOrBlank() && tags.isNullOrBlank() && tokens.isNullOrBlank()) null
            else LegacyVaultSections(ws, tags, tokens)
        } catch (_: Exception) {
            null
        }
    }

    override fun clearLegacy() {
        try {
            appContext.deleteSharedPreferences(LEGACY_PREF_NAME)
        } catch (_: Exception) {
            try {
                legacyPrefs.edit().clear().commit()
            } catch (_: Exception) {
            }
        }
    }

    private companion object {
        const val DOC_FILE_NAME = "vault_document.json"
        const val LEGACY_PREF_NAME = "my_2fa_secure_store"
        const val LEGACY_KEY_WORKSPACES = "workspaces_data"
        const val LEGACY_KEY_TAGS = "tags_data"
        const val LEGACY_KEY_TOKENS = "tokens_data"
    }
}

class TokenRepository private constructor(
    private val storage: VaultDocumentStorage,
    private val cipher: SecretCipher,
    private val clock: Clock,
    private val ioDispatcher: CoroutineDispatcher,
    private val isDebugBuild: Boolean
) : TokenVaultRepository {

    constructor(
        context: Context,
        cipher: SecretCipher = KeyStoreManager,
        clock: Clock = SystemClockImpl,
        ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        isDebugBuild: Boolean = false
    ) : this(
        storage = FileVaultDocumentStorage(context.applicationContext ?: context),
        cipher = cipher,
        clock = clock,
        ioDispatcher = ioDispatcher,
        isDebugBuild = isDebugBuild
    )

    internal constructor(
        storage: VaultDocumentStorage,
        cipher: SecretCipher,
        clock: Clock,
        ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        isDebugBuild: Boolean = false,
        @Suppress("UNUSED_PARAMETER") testMarker: Unit = Unit
    ) : this(storage, cipher, clock, ioDispatcher, isDebugBuild)

    private val gson = Gson()
    private val stateMutex = Mutex()
    private val repoScope = CoroutineScope(SupervisorJob() + ioDispatcher)
    private val encCache = ConcurrentHashMap<String, String>()
    private val sessionEpoch = AtomicLong(0L)
    private val hasPendingUsagePersist = AtomicBoolean(false)
    private var pendingUsagePersistJob: Job? = null

    @Volatile
    private var wiped = false

    @Volatile
    private var closed = false

    @Volatile
    private var locked = true

    @Volatile
    private var loadCorruptedReadOnly = false

    // 互斥锁保护的内部真值状态，绝不在无锁环境下从 lockInMemory 清空，杜绝并发覆盖磁盘
    private var allTokens: List<AuthToken> = emptyList()
    private var vaultWorkspaces: List<Workspace> = emptyList()
    private var vaultTags: List<Tag> = emptyList()

    private val _workspaces = MutableStateFlow<List<Workspace>>(emptyList())
    override val workspaces: StateFlow<List<Workspace>> = _workspaces.asStateFlow()

    private val _tags = MutableStateFlow<List<Tag>>(emptyList())
    override val tags: StateFlow<List<Tag>> = _tags.asStateFlow()

    private val _tokens = MutableStateFlow<List<AuthToken>>(emptyList())
    override val tokens: StateFlow<List<AuthToken>> = _tokens.asStateFlow()

    private val _trashedTokens = MutableStateFlow<List<AuthToken>>(emptyList())
    override val trashedTokens: StateFlow<List<AuthToken>> = _trashedTokens.asStateFlow()

    private val _isLoaded = MutableStateFlow(false)
    override val isLoaded: StateFlow<Boolean> = _isLoaded.asStateFlow()

    private val _isWiped = MutableStateFlow(false)
    override val isWiped: StateFlow<Boolean> = _isWiped.asStateFlow()

    private val _vaultLoadCorrupted = MutableStateFlow(false)
    override val vaultLoadCorrupted: StateFlow<Boolean> = _vaultLoadCorrupted.asStateFlow()

    override fun hasStoredEncryptedTokens(): Boolean {
        if (wiped) return false
        val docJson = try {
            storage.readDocumentJson()
        } catch (_: Exception) {
            null
        }
        if (!docJson.isNullOrBlank()) {
            val doc = safeParseDocument(docJson)
            if (doc != null) {
                return doc.tokens.isNotEmpty()
            }
            val bakDoc = try {
                safeParseDocument(storage.readBackupDocumentJson())
            } catch (_: Exception) {
                null
            }
            if (bakDoc != null) {
                return bakDoc.tokens.isNotEmpty()
            }
            // 主备文件存在但均无法解析时，仍视为曾存储有凭据以保留防降级告警
            return true
        }
        if (storage.hasAnyDocumentFile()) {
            val bakDoc = try {
                safeParseDocument(storage.readBackupDocumentJson())
            } catch (_: Exception) {
                null
            }
            return bakDoc?.tokens?.isNotEmpty() ?: true
        }
        return storage.hasLegacyTokens()
    }

    override suspend fun unlockAndLoad() {
        if (wiped || closed) return
        withContext(ioDispatcher) {
            stateMutex.withLock {
                if (wiped || closed || _isLoaded.value) return@withLock
                val startEpoch = sessionEpoch.get()
                locked = false
                loadCorruptedReadOnly = false

                val docJson = storage.readDocumentJson()
                val bakJson = if (docJson.isNullOrBlank() || safeParseDocument(docJson) == null) {
                    storage.readBackupDocumentJson()
                } else null
                val legacy = if (docJson.isNullOrBlank() && bakJson.isNullOrBlank()) {
                    storage.readLegacySections()
                } else null

                val rawWorkspaces: List<Workspace>
                val rawTags: List<Tag>
                val rawTokens: List<AuthToken>
                var needsPersist = false
                var allowEmptyTags = false
                var isCorruptedFallback = false

                if (!docJson.isNullOrBlank()) {
                    val parsedDoc = safeParseDocument(docJson)
                    if (parsedDoc != null) {
                        rawWorkspaces = parsedDoc.workspaces
                        rawTags = parsedDoc.tags
                        rawTokens = parsedDoc.tokens
                        allowEmptyTags = true
                    } else {
                        val parsedBak = safeParseDocument(bakJson)
                        if (parsedBak != null) {
                            rawWorkspaces = parsedBak.workspaces
                            rawTags = parsedBak.tags
                            rawTokens = parsedBak.tokens
                            allowEmptyTags = true
                            needsPersist = true
                        } else {
                            rawWorkspaces = defaultWorkspaces()
                            rawTags = defaultTags()
                            rawTokens = emptyList()
                            isCorruptedFallback = true
                        }
                    }
                } else if (!bakJson.isNullOrBlank()) {
                    val parsedBak = safeParseDocument(bakJson)
                    if (parsedBak != null) {
                        rawWorkspaces = parsedBak.workspaces
                        rawTags = parsedBak.tags
                        rawTokens = parsedBak.tokens
                        allowEmptyTags = true
                        needsPersist = true
                    } else {
                        rawWorkspaces = defaultWorkspaces()
                        rawTags = defaultTags()
                        rawTokens = emptyList()
                        isCorruptedFallback = true
                    }
                } else if (legacy != null) {
                    val wsType = object : TypeToken<List<Workspace>>() {}.type
                    val tagType = object : TypeToken<List<Tag>>() {}.type
                    val tokenType = object : TypeToken<List<AuthToken>>() {}.type
                    rawWorkspaces = safeParse(legacy.workspacesJson, wsType, defaultWorkspaces())
                    rawTags = safeParse(legacy.tagsJson, tagType, defaultTags())
                    rawTokens = safeParse(legacy.tokensJson, tokenType, emptyList())
                    needsPersist = true
                } else {
                    rawWorkspaces = defaultWorkspaces()
                    rawTags = defaultTags()
                    rawTokens = if (isDebugBuild) buildSeedDemoData() else emptyList()
                    needsPersist = rawTokens.isNotEmpty()
                }

                val normalizedWorkspaces = normalizeWorkspaceList(rawWorkspaces)
                val normalizedTags = normalizeTagList(rawTags, allowEmpty = allowEmptyTags)
                val fallbackWsId = normalizedWorkspaces.first().id
                val validWsIds = normalizedWorkspaces.map { it.id }.toHashSet()

                encCache.clear()
                val now = clock.currentTimeMillis()
                val cutoff = now - DEFAULT_TRASH_RETENTION_MS

                val loadedTokens = ArrayList<AuthToken>(rawTokens.size)
                var hasReconciledOrPurged = false
                val isFirstDebugSeed = docJson.isNullOrBlank() && bakJson.isNullOrBlank() && legacy == null && isDebugBuild

                for (item in rawTokens) {
                    val raw: AuthToken = (item as AuthToken?) ?: continue
                    val normalized = raw.normalize(fallbackWorkspaceId = fallbackWsId).let { t ->
                        if (t.workspaceId !in validWsIds) {
                            hasReconciledOrPurged = true
                            t.copy(workspaceId = fallbackWsId)
                        } else t
                    }

                    // 清理超期软删除凭据
                    val deletedAt = normalized.deletedAt
                    if (deletedAt != null && deletedAt <= cutoff) {
                        hasReconciledOrPurged = true
                        continue
                    }

                    val decrypted = if (normalized.secretInvalid) {
                        normalized
                    } else if (isFirstDebugSeed) {
                        // Debug 首次种子明文直接入内存并等待初次落盘加密
                        normalized
                    } else {
                        when (val r = cipher.decrypt(normalized.secret)) {
                            is SecretCipher.DecryptResult.Ok -> {
                                encCache[normalized.id] = normalized.secret
                                normalized.copy(secret = r.value, secretInvalid = false)
                            }
                            SecretCipher.DecryptResult.Empty ->
                                normalized.copy(secretInvalid = true)
                            is SecretCipher.DecryptResult.Corrupt,
                            is SecretCipher.DecryptResult.KeyInvalid ->
                                normalized.copy(secretInvalid = true)
                        }
                    }
                    loadedTokens.add(decrypted)
                }

                if (wiped || closed || locked || sessionEpoch.get() != startEpoch) return@withLock

                loadCorruptedReadOnly = isCorruptedFallback
                _vaultLoadCorrupted.value = isCorruptedFallback
                vaultWorkspaces = normalizedWorkspaces
                vaultTags = normalizedTags
                _workspaces.value = normalizedWorkspaces
                _tags.value = normalizedTags
                publishTokensLocked(loadedTokens)
                _isLoaded.value = true

                if (!isCorruptedFallback && (needsPersist || hasReconciledOrPurged)) {
                    persistLocked(startEpoch, loadedTokens, normalizedWorkspaces, normalizedTags)
                    if (legacy != null) {
                        storage.clearLegacy()
                    }
                }
            }
        }
    }

    override fun lockInMemory() {
        val prevEpoch = sessionEpoch.getAndIncrement()
        locked = true
        val hadPendingUsage = hasPendingUsagePersist.getAndSet(false)
        pendingUsagePersistJob?.cancel()
        pendingUsagePersistJob = null

        _isLoaded.value = false
        _tokens.value = emptyList()
        _trashedTokens.value = emptyList()
        _workspaces.value = emptyList()
        _tags.value = emptyList()

        // 绝不在 stateMutex 外部篡改 allTokens，避免并发 persistLocked 写出空库；
        // 若有待落盘的使用记录，异步于 ioDispatcher 冲刷后再清空内部缓存（不阻塞主线程）
        if (!hadPendingUsage && stateMutex.tryLock()) {
            try {
                encCache.clear()
                allTokens = emptyList()
                vaultWorkspaces = emptyList()
                vaultTags = emptyList()
            } finally {
                stateMutex.unlock()
            }
        } else {
            encCache.clear()
            repoScope.launch {
                stateMutex.withLock {
                    if (locked || wiped || closed) {
                        if (hadPendingUsage && !wiped && !closed && !loadCorruptedReadOnly && allTokens.isNotEmpty()) {
                            persistLocked(
                                expectedEpoch = prevEpoch,
                                tokensToSave = allTokens,
                                workspacesToSave = vaultWorkspaces,
                                tagsToSave = vaultTags,
                                allowWhileLocked = true
                            )
                        }
                        encCache.clear()
                        allTokens = emptyList()
                        vaultWorkspaces = emptyList()
                        vaultTags = emptyList()
                    }
                }
            }
        }
    }

    override fun wipeInMemoryImmediate() {
        wiped = true
        locked = true
        sessionEpoch.incrementAndGet()
        hasPendingUsagePersist.set(false)
        pendingUsagePersistJob?.cancel()
        pendingUsagePersistJob = null
        encCache.clear()
        _isWiped.value = true
        _isLoaded.value = false
        _vaultLoadCorrupted.value = false
        _tokens.value = emptyList()
        _trashedTokens.value = emptyList()
        _workspaces.value = emptyList()
        _tags.value = emptyList()
        if (stateMutex.tryLock()) {
            try {
                allTokens = emptyList()
                vaultWorkspaces = emptyList()
                vaultTags = emptyList()
            } finally {
                stateMutex.unlock()
            }
        }
    }

    override suspend fun wipeInMemoryState() {
        wipeInMemoryImmediate()
        stateMutex.withLock {
            encCache.clear()
            allTokens = emptyList()
            vaultWorkspaces = emptyList()
            vaultTags = emptyList()
            _isWiped.value = true
            _isLoaded.value = false
            _vaultLoadCorrupted.value = false
            _tokens.value = emptyList()
            _trashedTokens.value = emptyList()
            _workspaces.value = emptyList()
            _tags.value = emptyList()
        }
    }

    override suspend fun addToken(token: AuthToken) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val normalized = normalizeForWrite(token)
            val next = ArrayList<AuthToken>(allTokens.size + 1)
            next.add(normalized)
            next.addAll(allTokens)
            MutationResult(nextTokens = next)
        }
    }

    override suspend fun addTokens(tokens: List<AuthToken>) {
        if (wiped || closed || locked || tokens.isEmpty()) return
        mutateAndPersist {
            val normalized = tokens.map { normalizeForWrite(it) }
            val next = ArrayList<AuthToken>(allTokens.size + normalized.size)
            next.addAll(normalized)
            next.addAll(allTokens)
            MutationResult(nextTokens = next)
        }
    }

    override suspend fun addTokensDedup(tokens: List<AuthToken>): Pair<Int, Int> {
        if (wiped || closed || locked || tokens.isEmpty()) return 0 to 0
        return withContext(ioDispatcher) {
            stateMutex.withLock {
                if (wiped || closed || locked || !_isLoaded.value || loadCorruptedReadOnly) {
                    return@withLock 0 to 0
                }
                val startEpoch = sessionEpoch.get()
                val ids = allTokens.map { it.id }.toHashSet()
                val keys = allTokens.filter { it.deletedAt == null }.map { businessKey(it) }.toHashSet()
                val toAdd = ArrayList<AuthToken>()

                for (raw in tokens) {
                    val t = normalizeForWrite(raw)
                    val k = businessKey(t)
                    if (t.id in ids || k in keys) continue
                    ids.add(t.id)
                    if (t.deletedAt == null) keys.add(k)
                    toAdd.add(t)
                }

                if (toAdd.isEmpty()) {
                    return@withLock 0 to tokens.size
                }

                val merged = ArrayList<AuthToken>(toAdd.size + allTokens.size)
                merged.addAll(toAdd)
                merged.addAll(allTokens)
                val persisted = persistLocked(startEpoch, merged, vaultWorkspaces, vaultTags)
                if (!persisted) {
                    return@withLock 0 to tokens.size
                }
                publishTokensLocked(merged)
                hasPendingUsagePersist.set(false)
                pendingUsagePersistJob?.cancel()
                pendingUsagePersistJob = null
                toAdd.size to (tokens.size - toAdd.size)
            }
        }
    }

    override suspend fun updateToken(token: AuthToken) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == token.id }
            if (idx == -1) return@mutateAndPersist null
            val old = allTokens[idx]
            val updated = normalizeForWrite(token).copy(updatedAt = clock.currentTimeMillis())
            val secretChanged = old.secret != updated.secret || old.secretInvalid != updated.secretInvalid
            val next = allTokens.toMutableList()
            next[idx] = updated
            MutationResult(
                nextTokens = next,
                invalidateEncIds = if (secretChanged) listOf(updated.id) else emptyList()
            )
        }
    }

    override suspend fun advanceHotp(tokenId: String) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == tokenId }
            if (idx == -1) return@mutateAndPersist null
            val target = allTokens[idx]
            if (target.type != TokenType.HOTP || target.secretInvalid || target.deletedAt != null) {
                return@mutateAndPersist null
            }
            val now = clock.currentTimeMillis()
            val next = allTokens.toMutableList()
            next[idx] = target.copy(
                counter = target.counter + 1L,
                updatedAt = now,
                lastUsedAt = now,
                usageCount = target.usageCount + 1
            )
            MutationResult(nextTokens = next)
        }
    }

    override suspend fun togglePin(tokenId: String) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == tokenId }
            if (idx == -1) return@mutateAndPersist null
            val next = allTokens.toMutableList()
            val target = next[idx]
            next[idx] = target.copy(
                isPinned = !target.isPinned,
                updatedAt = clock.currentTimeMillis()
            )
            MutationResult(nextTokens = next)
        }
    }

    override suspend fun recordTokenUsed(tokenId: String) {
        if (wiped || closed || locked) return
        withContext(ioDispatcher) {
            stateMutex.withLock {
                if (wiped || closed || locked || !_isLoaded.value) return@withLock
                val idx = allTokens.indexOfFirst { it.id == tokenId }
                if (idx == -1) return@withLock
                val target = allTokens[idx]
                val next = allTokens.toMutableList()
                next[idx] = target.copy(
                    lastUsedAt = clock.currentTimeMillis(),
                    usageCount = target.usageCount + 1
                )
                publishTokensLocked(next)
                if (!loadCorruptedReadOnly) {
                    hasPendingUsagePersist.set(true)
                    scheduleUsagePersistLocked(sessionEpoch.get())
                }
            }
        }
    }

    override suspend fun softDeleteToken(id: String) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == id }
            if (idx == -1) return@mutateAndPersist null
            val target = allTokens[idx]
            if (target.deletedAt != null) return@mutateAndPersist null
            val now = clock.currentTimeMillis()
            val next = allTokens.toMutableList()
            next[idx] = target.copy(deletedAt = now, updatedAt = now)
            MutationResult(nextTokens = next)
        }
    }

    override suspend fun restoreToken(id: String) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == id }
            if (idx == -1) return@mutateAndPersist null
            val target = allTokens[idx]
            if (target.deletedAt == null) return@mutateAndPersist null
            val fallbackWsId = vaultWorkspaces.firstOrNull()?.id ?: Workspace.DEFAULT_PERSONAL.id
            val validWs = vaultWorkspaces.any { it.id == target.workspaceId }
            val next = allTokens.toMutableList()
            next[idx] = target.copy(
                deletedAt = null,
                workspaceId = if (validWs) target.workspaceId else fallbackWsId,
                updatedAt = clock.currentTimeMillis()
            )
            MutationResult(nextTokens = next)
        }
    }

    override suspend fun permanentlyDeleteToken(id: String) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val next = allTokens.filter { it.id != id }
            if (next.size == allTokens.size) return@mutateAndPersist null
            MutationResult(nextTokens = next, removeEncIds = listOf(id))
        }
    }

    override suspend fun emptyTrash() {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val removedIds = allTokens.filter { it.deletedAt != null }.map { it.id }
            if (removedIds.isEmpty()) return@mutateAndPersist null
            MutationResult(
                nextTokens = allTokens.filter { it.deletedAt == null },
                removeEncIds = removedIds
            )
        }
    }

    override suspend fun purgeExpiredTrash(retentionMillis: Long) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val cutoff = clock.currentTimeMillis() - retentionMillis.coerceAtLeast(0L)
            val expiredIds = allTokens
                .filter { token ->
                    val deletedAt = token.deletedAt
                    deletedAt != null && deletedAt <= cutoff
                }
                .map { it.id }
            if (expiredIds.isEmpty()) return@mutateAndPersist null
            val expiredSet = expiredIds.toHashSet()
            MutationResult(
                nextTokens = allTokens.filter { it.id !in expiredSet },
                removeEncIds = expiredIds
            )
        }
    }

    override suspend fun clearAllTokens() {
        if (wiped || closed || locked) return
        mutateAndPersist {
            MutationResult(
                nextTokens = emptyList(),
                clearAllEnc = true
            )
        }
    }

    override suspend fun addTag(tag: Tag) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val normalized = tag.normalize()
            MutationResult(nextTags = vaultTags + normalized)
        }
    }

    override suspend fun addTagIfAbsent(tag: Tag) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val normalized = tag.normalize()
            if (vaultTags.any { it.id == normalized.id }) return@mutateAndPersist null
            MutationResult(nextTags = vaultTags + normalized)
        }
    }

    override suspend fun deleteTag(tagId: String) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val nextTags = vaultTags.filter { it.id != tagId }
            val nextTokens = allTokens.map { token ->
                if (token.tagIds.contains(tagId)) {
                    token.copy(tagIds = token.tagIds.filter { it != tagId })
                } else token
            }
            if (nextTags.size == vaultTags.size && nextTokens == allTokens) {
                return@mutateAndPersist null
            }
            MutationResult(nextTokens = nextTokens, nextTags = nextTags)
        }
    }

    override suspend fun addWorkspace(workspace: Workspace) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val normalized = workspace.normalize()
            val nextOrder = (vaultWorkspaces.maxOfOrNull { it.orderIndex } ?: -1) + 1
            val toInsert = if (normalized.orderIndex == 0 && vaultWorkspaces.isNotEmpty()) {
                normalized.copy(orderIndex = nextOrder)
            } else normalized
            MutationResult(nextWorkspaces = vaultWorkspaces + toInsert)
        }
    }

    override suspend fun addWorkspaceIfAbsent(workspace: Workspace) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val normalized = workspace.normalize()
            if (vaultWorkspaces.any { it.id == normalized.id }) return@mutateAndPersist null
            MutationResult(nextWorkspaces = vaultWorkspaces + normalized)
        }
    }

    override suspend fun renameWorkspace(workspaceId: String, newName: String) {
        if (wiped || closed || locked) return
        val trimmed = newName.trim()
        if (trimmed.isEmpty()) return
        mutateAndPersist {
            val current = vaultWorkspaces
            val idx = current.indexOfFirst { it.id == workspaceId }
            if (idx == -1) return@mutateAndPersist null
            val next = current.toMutableList()
            next[idx] = next[idx].copy(name = trimmed)
            MutationResult(nextWorkspaces = next)
        }
    }

    override suspend fun updateWorkspacesOrder(orderedIds: List<String>) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val current = vaultWorkspaces
            if (current.isEmpty()) return@mutateAndPersist null
            val byId = current.associateBy { it.id }
            val reordered = ArrayList<Workspace>(current.size)
            val seen = HashSet<String>()
            for (id in orderedIds) {
                val ws = byId[id]
                if (ws != null && seen.add(id)) {
                    reordered.add(ws)
                }
            }
            for (ws in current) {
                if (seen.add(ws.id)) {
                    reordered.add(ws)
                }
            }
            MutationResult(
                nextWorkspaces = reordered.mapIndexed { index, ws -> ws.copy(orderIndex = index) }
            )
        }
    }

    override suspend fun deleteWorkspace(workspaceId: String) {
        if (wiped || closed || locked) return
        mutateAndPersist {
            val currentWs = vaultWorkspaces
            if (currentWs.size <= 1) return@mutateAndPersist null
            if (currentWs.none { it.id == workspaceId }) return@mutateAndPersist null

            val defaultWsId = currentWs.first { it.id != workspaceId }.id
            val updatedTokens = allTokens.map {
                if (it.workspaceId == workspaceId) it.copy(workspaceId = defaultWsId) else it
            }
            val updatedWorkspaces = currentWs.filter { it.id != workspaceId }
                .mapIndexed { index, ws -> ws.copy(orderIndex = index) }

            MutationResult(nextTokens = updatedTokens, nextWorkspaces = updatedWorkspaces)
        }
    }

    override fun close() {
        closed = true
        locked = true
        sessionEpoch.incrementAndGet()
        hasPendingUsagePersist.set(false)
        pendingUsagePersistJob?.cancel()
        pendingUsagePersistJob = null
        encCache.clear()
        repoScope.cancel()
    }

    private data class MutationResult(
        val nextTokens: List<AuthToken>? = null,
        val nextWorkspaces: List<Workspace>? = null,
        val nextTags: List<Tag>? = null,
        val invalidateEncIds: List<String> = emptyList(),
        val removeEncIds: List<String> = emptyList(),
        val clearAllEnc: Boolean = false
    )

    private fun scheduleUsagePersistLocked(epoch: Long) {
        pendingUsagePersistJob?.cancel()
        pendingUsagePersistJob = repoScope.launch {
            delay(USAGE_PERSIST_DEBOUNCE_MS)
            stateMutex.withLock {
                if (!hasPendingUsagePersist.getAndSet(false)) return@withLock
                if (wiped || closed || locked || !_isLoaded.value || loadCorruptedReadOnly) return@withLock
                if (sessionEpoch.get() != epoch) return@withLock
                persistLocked(epoch, allTokens, vaultWorkspaces, vaultTags)
            }
        }
    }

    private suspend inline fun mutateAndPersist(crossinline mutation: () -> MutationResult?) {
        withContext(ioDispatcher) {
            stateMutex.withLock {
                if (wiped || closed || locked || !_isLoaded.value || loadCorruptedReadOnly) return@withLock
                val startEpoch = sessionEpoch.get()
                val res = mutation() ?: return@withLock

                val candidateTokens = res.nextTokens ?: allTokens
                val candidateWorkspaces = res.nextWorkspaces ?: vaultWorkspaces
                val candidateTags = res.nextTags ?: vaultTags

                val persisted = persistLocked(
                    expectedEpoch = startEpoch,
                    tokensToSave = candidateTokens,
                    workspacesToSave = candidateWorkspaces,
                    tagsToSave = candidateTags,
                    skipEncIds = res.invalidateEncIds.toHashSet()
                )
                if (!persisted) return@withLock

                if (res.clearAllEnc) {
                    encCache.clear()
                } else {
                    res.removeEncIds.forEach { encCache.remove(it) }
                }

                if (res.nextWorkspaces != null) {
                    vaultWorkspaces = candidateWorkspaces
                    _workspaces.value = candidateWorkspaces
                }
                if (res.nextTags != null) {
                    vaultTags = candidateTags
                    _tags.value = candidateTags
                }
                if (res.nextTokens != null) {
                    publishTokensLocked(candidateTokens)
                }

                hasPendingUsagePersist.set(false)
                pendingUsagePersistJob?.cancel()
                pendingUsagePersistJob = null
            }
        }
    }

    private fun publishTokensLocked(tokens: List<AuthToken>) {
        allTokens = tokens
        _tokens.value = tokens.filter { it.deletedAt == null }
        _trashedTokens.value = tokens.filter { it.deletedAt != null }
    }

    private fun persistLocked(
        expectedEpoch: Long,
        tokensToSave: List<AuthToken>,
        workspacesToSave: List<Workspace>,
        tagsToSave: List<Tag>,
        skipEncIds: Set<String> = emptySet(),
        allowWhileLocked: Boolean = false
    ): Boolean {
        if (wiped || closed || loadCorruptedReadOnly) return false
        if (!allowWhileLocked && (locked || sessionEpoch.get() != expectedEpoch)) return false

        val newCacheEntries = HashMap<String, String>()
        val encryptedTokens = ArrayList<AuthToken>(tokensToSave.size)
        for (token in tokensToSave) {
            if (token.secretInvalid) {
                encryptedTokens.add(token)
                continue
            }
            val cached = if (token.id in skipEncIds) null else encCache[token.id]
            if (cached != null) {
                encryptedTokens.add(token.copy(secret = cached))
                continue
            }
            when (val enc = cipher.encrypt(token.secret)) {
                is SecretCipher.EncryptResult.Ok -> {
                    newCacheEntries[token.id] = enc.cipherTextBase64
                    encryptedTokens.add(token.copy(secret = enc.cipherTextBase64))
                }
                is SecretCipher.EncryptResult.Failed -> {
                    // 绝不将明文写入磁盘，也绝不覆写已有的有效密文
                    return false
                }
            }
        }

        if (wiped || closed) return false
        if (!allowWhileLocked && (locked || sessionEpoch.get() != expectedEpoch)) return false

        val document = VaultDocument(
            schemaVersion = CURRENT_VAULT_SCHEMA_VERSION,
            workspaces = workspacesToSave,
            tags = tagsToSave,
            tokens = encryptedTokens
        )
        return try {
            storage.writeDocumentJson(gson.toJson(document))
            if (!wiped && !closed) {
                encCache.putAll(newCacheEntries)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun normalizeForWrite(token: AuthToken): AuthToken {
        val fallbackWsId = vaultWorkspaces.firstOrNull()?.id ?: Workspace.DEFAULT_PERSONAL.id
        val validWsIds = vaultWorkspaces.map { it.id }.toHashSet()
        val normalized = token.normalize(fallbackWorkspaceId = fallbackWsId)
        return if (validWsIds.isNotEmpty() && normalized.workspaceId !in validWsIds) {
            normalized.copy(workspaceId = fallbackWsId)
        } else {
            normalized
        }
    }

    private fun businessKey(t: AuthToken): String =
        "${t.workspaceId}|${t.issuer.trim().lowercase(Locale.US)}|${t.accountName.trim().lowercase(Locale.US)}"

    private fun normalizeWorkspaceList(raw: List<Workspace>): List<Workspace> {
        @Suppress("USELESS_ELVIS")
        val cleaned = raw.filterNotNull().map { it.normalize() }
        return if (cleaned.isEmpty()) defaultWorkspaces()
        else cleaned.sortedBy { it.orderIndex }
    }

    private fun normalizeTagList(raw: List<Tag>, allowEmpty: Boolean): List<Tag> {
        @Suppress("USELESS_ELVIS")
        val cleaned = raw.filterNotNull().map { it.normalize() }
        return if (cleaned.isEmpty() && !allowEmpty) defaultTags() else cleaned
    }

    private fun defaultWorkspaces(): List<Workspace> = listOf(
        Workspace.DEFAULT_PERSONAL,
        Workspace.DEFAULT_WORK,
        Workspace.DEFAULT_DEVOPS
    )

    private fun defaultTags(): List<Tag> = listOf(
        Tag.TAG_MAIN,
        Tag.TAG_SUB,
        Tag.TAG_ASSET,
        Tag.TAG_DEV
    )

    private fun safeParseDocument(json: String?): VaultDocument? {
        if (json.isNullOrBlank()) return null
        return try {
            val parsed = gson.fromJson(json, VaultDocument::class.java) ?: return null
            @Suppress("USELESS_ELVIS")
            VaultDocument(
                schemaVersion = parsed.schemaVersion,
                workspaces = parsed.workspaces ?: emptyList(),
                tags = parsed.tags ?: emptyList(),
                tokens = parsed.tokens ?: emptyList()
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun <T> safeParse(json: String?, type: java.lang.reflect.Type, fallback: T): T =
        try {
            if (json.isNullOrEmpty()) fallback else (gson.fromJson<T>(json, type) ?: fallback)
        } catch (_: Exception) {
            fallback
        }

    private fun buildSeedDemoData(): List<AuthToken> = listOf(
        AuthToken(
            workspaceId = Workspace.DEFAULT_PERSONAL.id,
            issuer = "Google",
            accountName = "primary@example.com",
            tenantEnv = "主力邮箱",
            tagIds = listOf(Tag.TAG_MAIN.id),
            secret = "JBSWY3DPEHPK3PXP",
            isPinned = true,
            note = "主账号：绑定银行、手机与关键服务"
        ),
        AuthToken(
            workspaceId = Workspace.DEFAULT_PERSONAL.id,
            issuer = "Google",
            accountName = "demo.sub@example.com",
            tenantEnv = "注册小号",
            tagIds = listOf(Tag.TAG_SUB.id),
            secret = "JBSWY3DPEHPK3PXP",
            note = "辅助账号：日常测试与论坛注册"
        ),
        AuthToken(
            workspaceId = Workspace.DEFAULT_WORK.id,
            issuer = "GitHub",
            accountName = "enterprise-corp-lead",
            tenantEnv = "公司企业版",
            tagIds = listOf(Tag.TAG_MAIN.id),
            secret = "JBSWY3DPEHPK3PXP",
            isPinned = true,
            note = "包含组织核心仓库权限"
        ),
        AuthToken(
            workspaceId = Workspace.DEFAULT_PERSONAL.id,
            issuer = "GitHub",
            accountName = "my-open-source-id",
            tenantEnv = "个人极客号",
            tagIds = listOf(Tag.TAG_SUB.id),
            secret = "JBSWY3DPEHPK3PXP"
        ),
        AuthToken(
            workspaceId = Workspace.DEFAULT_DEVOPS.id,
            issuer = "Amazon Web Services",
            accountName = "root-admin@company.com",
            tenantEnv = "Prod-亚太主集群",
            tagIds = listOf(Tag.TAG_MAIN.id, Tag.TAG_ASSET.id),
            secret = "JBSWY3DPEHPK3PXP",
            isPinned = true,
            note = "支付集群，严禁误登"
        ),
        AuthToken(
            workspaceId = Workspace.DEFAULT_DEVOPS.id,
            issuer = "Amazon Web Services",
            accountName = "dev-sre@company.com",
            tenantEnv = "Dev-沙箱测试环境",
            tagIds = listOf(Tag.TAG_DEV.id),
            secret = "JBSWY3DPEHPK3PXP"
        )
    )

    companion object {
        const val DEFAULT_TRASH_RETENTION_MS = 7L * 24 * 60 * 60 * 1000
        private const val USAGE_PERSIST_DEBOUNCE_MS = 2_000L
    }
}
