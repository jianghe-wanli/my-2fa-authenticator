package com.f2a.authenticator.data.local

import android.content.Context
import android.content.SharedPreferences
import com.f2a.authenticator.crypto.KeyStoreManager
import com.f2a.authenticator.crypto.SecretCipher
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.CURRENT_VAULT_SCHEMA_VERSION
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.Clock
import com.f2a.authenticator.security.SystemClockImpl
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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
    fun writeDocumentJson(json: String)
    fun hasLegacyTokens(): Boolean
    fun readLegacySections(): LegacyVaultSections?
    fun clearLegacy()
}

private class FileVaultDocumentStorage(context: Context) : VaultDocumentStorage {
    private val appContext = context.applicationContext ?: context
    private val docFile = File(appContext.filesDir, DOC_FILE_NAME)
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
    private val encCache = ConcurrentHashMap<String, String>()
    private val sessionEpoch = AtomicLong(0L)

    @Volatile
    private var wiped = false

    @Volatile
    private var closed = false

    private var allTokens: List<AuthToken> = emptyList()

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

    override fun hasStoredEncryptedTokens(): Boolean {
        if (wiped) return false
        val docJson = try {
            storage.readDocumentJson()
        } catch (_: Exception) {
            null
        }
        if (!docJson.isNullOrBlank()) {
            val doc = safeParseDocument(docJson)
            return doc?.tokens?.isNotEmpty() == true
        }
        return storage.hasLegacyTokens()
    }

    override suspend fun unlockAndLoad() {
        if (wiped || closed) return
        withContext(ioDispatcher) {
            stateMutex.withLock {
                if (wiped || closed || _isLoaded.value) return@withLock
                val startEpoch = sessionEpoch.get()

                val docJson = storage.readDocumentJson()
                val legacy = if (docJson.isNullOrBlank()) storage.readLegacySections() else null

                val rawWorkspaces: List<Workspace>
                val rawTags: List<Tag>
                val rawTokens: List<AuthToken>
                var needsPersist = false

                if (!docJson.isNullOrBlank()) {
                    val parsedDoc = safeParseDocument(docJson)
                    if (parsedDoc != null) {
                        rawWorkspaces = parsedDoc.workspaces
                        rawTags = parsedDoc.tags
                        rawTokens = parsedDoc.tokens
                    } else {
                        rawWorkspaces = defaultWorkspaces()
                        rawTags = defaultTags()
                        rawTokens = emptyList()
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
                val normalizedTags = normalizeTagList(rawTags)
                val fallbackWsId = normalizedWorkspaces.first().id
                val validWsIds = normalizedWorkspaces.map { it.id }.toHashSet()

                encCache.clear()
                val now = clock.currentTimeMillis()
                val cutoff = now - DEFAULT_TRASH_RETENTION_MS

                val loadedTokens = ArrayList<AuthToken>(rawTokens.size)
                var hasReconciledOrPurged = false

                @Suppress("USELESS_ELVIS")
                for (raw in rawTokens) {
                    if (raw == null) continue
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
                    } else if (docJson.isNullOrBlank() && legacy == null && isDebugBuild) {
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

                if (wiped || closed || sessionEpoch.get() != startEpoch) return@withLock

                _workspaces.value = normalizedWorkspaces
                _tags.value = normalizedTags
                publishTokensLocked(loadedTokens)
                _isLoaded.value = true

                if (needsPersist || hasReconciledOrPurged) {
                    persistLocked()
                    if (legacy != null) {
                        storage.clearLegacy()
                    }
                }
            }
        }
    }

    override fun lockInMemory() {
        sessionEpoch.incrementAndGet()
        encCache.clear()
        allTokens = emptyList()
        _isLoaded.value = false
        _tokens.value = emptyList()
        _trashedTokens.value = emptyList()
        _workspaces.value = emptyList()
        _tags.value = emptyList()
    }

    override suspend fun wipeInMemoryState() {
        wiped = true
        sessionEpoch.incrementAndGet()
        encCache.clear()
        allTokens = emptyList()
        _isLoaded.value = false
        _tokens.value = emptyList()
        _trashedTokens.value = emptyList()
        _workspaces.value = emptyList()
        _tags.value = emptyList()

        stateMutex.withLock {
            encCache.clear()
            allTokens = emptyList()
            _isLoaded.value = false
            _tokens.value = emptyList()
            _trashedTokens.value = emptyList()
            _workspaces.value = emptyList()
            _tags.value = emptyList()
        }
    }

    override suspend fun addToken(token: AuthToken) {
        if (wiped || closed) return
        mutateAndPersist {
            val normalized = normalizeForWrite(token)
            val next = ArrayList<AuthToken>(allTokens.size + 1)
            next.add(normalized)
            next.addAll(allTokens)
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun addTokens(tokens: List<AuthToken>) {
        if (wiped || closed || tokens.isEmpty()) return
        mutateAndPersist {
            val normalized = tokens.map { normalizeForWrite(it) }
            val next = ArrayList<AuthToken>(allTokens.size + normalized.size)
            next.addAll(normalized)
            next.addAll(allTokens)
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun addTokensDedup(tokens: List<AuthToken>): Pair<Int, Int> {
        if (wiped || closed || tokens.isEmpty()) return 0 to 0
        return withContext(ioDispatcher) {
            stateMutex.withLock {
                if (wiped || closed) return@withLock 0 to 0
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

                if (toAdd.isNotEmpty()) {
                    val merged = ArrayList<AuthToken>(toAdd.size + allTokens.size)
                    merged.addAll(toAdd)
                    merged.addAll(allTokens)
                    publishTokensLocked(merged)
                    persistLocked()
                }
                toAdd.size to (tokens.size - toAdd.size)
            }
        }
    }

    override suspend fun updateToken(token: AuthToken) {
        if (wiped || closed) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == token.id }
            if (idx == -1) return@mutateAndPersist false
            val old = allTokens[idx]
            val updated = normalizeForWrite(token).copy(updatedAt = clock.currentTimeMillis())
            if (old.secret != updated.secret || old.secretInvalid != updated.secretInvalid) {
                encCache.remove(updated.id)
            }
            val next = allTokens.toMutableList()
            next[idx] = updated
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun advanceHotp(tokenId: String) {
        if (wiped || closed) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == tokenId }
            if (idx == -1) return@mutateAndPersist false
            val target = allTokens[idx]
            val now = clock.currentTimeMillis()
            val next = allTokens.toMutableList()
            next[idx] = target.copy(
                counter = target.counter + 1L,
                updatedAt = now,
                lastUsedAt = now
            )
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun togglePin(tokenId: String) {
        if (wiped || closed) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == tokenId }
            if (idx == -1) return@mutateAndPersist false
            val next = allTokens.toMutableList()
            val target = next[idx]
            next[idx] = target.copy(
                isPinned = !target.isPinned,
                updatedAt = clock.currentTimeMillis()
            )
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun recordTokenUsed(tokenId: String) {
        if (wiped || closed) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == tokenId }
            if (idx == -1) return@mutateAndPersist false
            val next = allTokens.toMutableList()
            next[idx] = next[idx].copy(lastUsedAt = clock.currentTimeMillis())
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun softDeleteToken(id: String) {
        if (wiped || closed) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == id }
            if (idx == -1) return@mutateAndPersist false
            val target = allTokens[idx]
            if (target.deletedAt != null) return@mutateAndPersist false
            val now = clock.currentTimeMillis()
            val next = allTokens.toMutableList()
            next[idx] = target.copy(deletedAt = now, updatedAt = now)
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun restoreToken(id: String) {
        if (wiped || closed) return
        mutateAndPersist {
            val idx = allTokens.indexOfFirst { it.id == id }
            if (idx == -1) return@mutateAndPersist false
            val target = allTokens[idx]
            if (target.deletedAt == null) return@mutateAndPersist false
            val fallbackWsId = _workspaces.value.firstOrNull()?.id ?: Workspace.DEFAULT_PERSONAL.id
            val validWs = _workspaces.value.any { it.id == target.workspaceId }
            val next = allTokens.toMutableList()
            next[idx] = target.copy(
                deletedAt = null,
                workspaceId = if (validWs) target.workspaceId else fallbackWsId,
                updatedAt = clock.currentTimeMillis()
            )
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun permanentlyDeleteToken(id: String) {
        if (wiped || closed) return
        mutateAndPersist {
            val next = allTokens.filter { it.id != id }
            if (next.size == allTokens.size) return@mutateAndPersist false
            encCache.remove(id)
            publishTokensLocked(next)
            true
        }
    }

    override suspend fun emptyTrash() {
        if (wiped || closed) return
        mutateAndPersist {
            val removedIds = allTokens.filter { it.deletedAt != null }.map { it.id }
            if (removedIds.isEmpty()) return@mutateAndPersist false
            removedIds.forEach { encCache.remove(it) }
            publishTokensLocked(allTokens.filter { it.deletedAt == null })
            true
        }
    }

    override suspend fun purgeExpiredTrash(retentionMillis: Long) {
        if (wiped || closed) return
        mutateAndPersist {
            val cutoff = clock.currentTimeMillis() - retentionMillis.coerceAtLeast(0L)
            val expiredIds = allTokens
                .filter { token ->
                    val deletedAt = token.deletedAt
                    deletedAt != null && deletedAt <= cutoff
                }
                .map { it.id }
            if (expiredIds.isEmpty()) return@mutateAndPersist false
            val expiredSet = expiredIds.toHashSet()
            expiredIds.forEach { encCache.remove(it) }
            publishTokensLocked(allTokens.filter { it.id !in expiredSet })
            true
        }
    }

    override suspend fun clearAllTokens() {
        if (wiped || closed) return
        mutateAndPersist {
            encCache.clear()
            publishTokensLocked(emptyList())
            true
        }
    }

    override suspend fun addTag(tag: Tag) {
        if (wiped || closed) return
        mutateAndPersist {
            val normalized = tag.normalize()
            _tags.value = _tags.value + normalized
            true
        }
    }

    override suspend fun addTagIfAbsent(tag: Tag) {
        if (wiped || closed) return
        mutateAndPersist {
            val normalized = tag.normalize()
            if (_tags.value.any { it.id == normalized.id }) return@mutateAndPersist false
            _tags.value = _tags.value + normalized
            true
        }
    }

    override suspend fun deleteTag(tagId: String) {
        if (wiped || closed) return
        mutateAndPersist {
            val nextTags = _tags.value.filter { it.id != tagId }
            val nextTokens = allTokens.map { token ->
                if (token.tagIds.contains(tagId)) {
                    token.copy(tagIds = token.tagIds.filter { it != tagId })
                } else token
            }
            if (nextTags.size == _tags.value.size && nextTokens == allTokens) {
                return@mutateAndPersist false
            }
            _tags.value = nextTags
            publishTokensLocked(nextTokens)
            true
        }
    }

    override suspend fun addWorkspace(workspace: Workspace) {
        if (wiped || closed) return
        mutateAndPersist {
            val normalized = workspace.normalize()
            val nextOrder = (_workspaces.value.maxOfOrNull { it.orderIndex } ?: -1) + 1
            val toInsert = if (normalized.orderIndex == 0 && _workspaces.value.isNotEmpty()) {
                normalized.copy(orderIndex = nextOrder)
            } else normalized
            _workspaces.value = _workspaces.value + toInsert
            true
        }
    }

    override suspend fun addWorkspaceIfAbsent(workspace: Workspace) {
        if (wiped || closed) return
        mutateAndPersist {
            val normalized = workspace.normalize()
            if (_workspaces.value.any { it.id == normalized.id }) return@mutateAndPersist false
            _workspaces.value = _workspaces.value + normalized
            true
        }
    }

    override suspend fun renameWorkspace(workspaceId: String, newName: String) {
        if (wiped || closed) return
        val trimmed = newName.trim()
        if (trimmed.isEmpty()) return
        mutateAndPersist {
            val current = _workspaces.value
            val idx = current.indexOfFirst { it.id == workspaceId }
            if (idx == -1) return@mutateAndPersist false
            val next = current.toMutableList()
            next[idx] = next[idx].copy(name = trimmed)
            _workspaces.value = next
            true
        }
    }

    override suspend fun updateWorkspacesOrder(orderedIds: List<String>) {
        if (wiped || closed) return
        mutateAndPersist {
            val current = _workspaces.value
            if (current.isEmpty()) return@mutateAndPersist false
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
            _workspaces.value = reordered.mapIndexed { index, ws -> ws.copy(orderIndex = index) }
            true
        }
    }

    override suspend fun deleteWorkspace(workspaceId: String) {
        if (wiped || closed) return
        mutateAndPersist {
            val currentWs = _workspaces.value
            if (currentWs.size <= 1) return@mutateAndPersist false
            if (currentWs.none { it.id == workspaceId }) return@mutateAndPersist false

            val defaultWsId = currentWs.first { it.id != workspaceId }.id
            val updatedTokens = allTokens.map {
                if (it.workspaceId == workspaceId) it.copy(workspaceId = defaultWsId) else it
            }
            val updatedWorkspaces = currentWs.filter { it.id != workspaceId }
                .mapIndexed { index, ws -> ws.copy(orderIndex = index) }

            _workspaces.value = updatedWorkspaces
            publishTokensLocked(updatedTokens)
            true
        }
    }

    override fun close() {
        closed = true
        encCache.clear()
    }

    private suspend inline fun mutateAndPersist(crossinline mutation: () -> Boolean) {
        withContext(ioDispatcher) {
            stateMutex.withLock {
                if (wiped || closed) return@withLock
                if (mutation()) {
                    persistLocked()
                }
            }
        }
    }

    private fun publishTokensLocked(tokens: List<AuthToken>) {
        allTokens = tokens
        _tokens.value = tokens.filter { it.deletedAt == null }
        _trashedTokens.value = tokens.filter { it.deletedAt != null }
    }

    private fun persistLocked() {
        if (wiped || closed) return
        val encryptedTokens = allTokens.map { token ->
            if (token.secretInvalid) {
                token
            } else {
                val cached = encCache[token.id]
                if (cached != null) {
                    token.copy(secret = cached)
                } else {
                    when (val enc = cipher.encrypt(token.secret)) {
                        is SecretCipher.EncryptResult.Ok -> {
                            encCache[token.id] = enc.cipherTextBase64
                            token.copy(secret = enc.cipherTextBase64)
                        }
                        is SecretCipher.EncryptResult.Failed -> {
                            // 绝不将明文写入磁盘
                            token.copy(secret = "", secretInvalid = true)
                        }
                    }
                }
            }
        }
        if (wiped || closed) return
        val document = VaultDocument(
            schemaVersion = CURRENT_VAULT_SCHEMA_VERSION,
            workspaces = _workspaces.value,
            tags = _tags.value,
            tokens = encryptedTokens
        )
        storage.writeDocumentJson(gson.toJson(document))
    }

    private fun normalizeForWrite(token: AuthToken): AuthToken {
        val fallbackWsId = _workspaces.value.firstOrNull()?.id ?: Workspace.DEFAULT_PERSONAL.id
        val validWsIds = _workspaces.value.map { it.id }.toHashSet()
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

    private fun normalizeTagList(raw: List<Tag>): List<Tag> {
        @Suppress("USELESS_ELVIS")
        val cleaned = raw.filterNotNull().map { it.normalize() }
        return if (cleaned.isEmpty()) defaultTags() else cleaned
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
    }
}
