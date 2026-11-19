package com.f2a.authenticator.data.local

import android.content.Context
import android.content.SharedPreferences
import com.f2a.authenticator.data.model.AutoLockTimeout
import com.f2a.authenticator.data.model.CollapsePolicy
import com.f2a.authenticator.data.model.SortMode
import com.f2a.authenticator.data.model.ThemeMode
import com.f2a.authenticator.data.model.VaultPreferences
import com.google.gson.Gson
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

internal interface PreferencesStorage {
    fun readJson(): String?
    fun writeJson(json: String)
    fun clear()
}

private class SharedPreferencesPrefStorage(context: Context) : PreferencesStorage {
    private val prefs: SharedPreferences =
        (context.applicationContext ?: context).getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    override fun readJson(): String? = prefs.getString(KEY_PREFS_JSON, null)

    override fun writeJson(json: String) {
        prefs.edit().putString(KEY_PREFS_JSON, json).commit()
    }

    override fun clear() {
        prefs.edit().clear().commit()
    }

    private companion object {
        const val PREF_NAME = "my_2fa_vault_prefs"
        const val KEY_PREFS_JSON = "vault_preferences_json"
    }
}

class VaultPreferencesStore private constructor(
    private val storage: PreferencesStorage,
    private val asyncPersist: Boolean
) : VaultPreferencesRepository {

    constructor(context: Context) : this(
        storage = SharedPreferencesPrefStorage(context),
        asyncPersist = true
    )

    internal constructor(
        storage: PreferencesStorage,
        @Suppress("UNUSED_PARAMETER") marker: Unit = Unit
    ) : this(storage = storage, asyncPersist = false)

    private val gson = Gson()
    private val lock = Any()
    private val diskLock = Any()
    private val writeGeneration = AtomicLong(0L)
    private val persistExecutor: ExecutorService? = if (asyncPersist) {
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "f2a-prefs-io").apply { isDaemon = true }
        }
    } else {
        null
    }

    private val _preferences = MutableStateFlow(loadInitial())
    override val preferences: StateFlow<VaultPreferences> = _preferences.asStateFlow()

    private fun loadInitial(): VaultPreferences {
        val json = try {
            storage.readJson()
        } catch (_: Exception) {
            null
        }
        if (json.isNullOrBlank()) return VaultPreferences()
        return try {
            val parsed = gson.fromJson(json, VaultPreferences::class.java)
            normalize(parsed)
        } catch (_: Exception) {
            VaultPreferences()
        }
    }

    @Suppress("USELESS_ELVIS")
    private fun normalize(raw: VaultPreferences?): VaultPreferences {
        if (raw == null) return VaultPreferences()
        val rawMap: Map<String, Set<String>> = raw.expandedIssuerKeys ?: emptyMap()
        val safeMap = LinkedHashMap<String, Set<String>>()
        for ((k, v) in rawMap) {
            val safeWs = (k ?: "").trim()
            if (safeWs.isEmpty()) continue
            val safeSet = (v ?: emptySet())
                .mapNotNull { it?.trim()?.lowercase(Locale.US) }
                .filter { it.isNotEmpty() }
                .toSet()
            safeMap[safeWs] = safeSet
        }
        return VaultPreferences(
            collapsePolicy = raw.collapsePolicy ?: CollapsePolicy.COLLAPSE_ALL,
            sortMode = raw.sortMode ?: SortMode.PINNED_AND_COUNT,
            themeMode = raw.themeMode ?: ThemeMode.SYSTEM,
            autoLockTimeout = raw.autoLockTimeout ?: AutoLockTimeout.SECONDS_30,
            expandedIssuerKeys = safeMap,
            lastActiveWorkspaceId = (raw.lastActiveWorkspaceId ?: "").ifBlank { "all" },
            privacyMaskEnabled = raw.privacyMaskEnabled,
            lastBackupAtMillis = raw.lastBackupAtMillis?.takeIf { it > 0L },
            lastBackupTokenCount = raw.lastBackupTokenCount.coerceAtLeast(0)
        )
    }

    private inline fun updatePreferences(transform: (VaultPreferences) -> VaultPreferences) {
        val jsonToWrite: String
        val gen: Long
        synchronized(lock) {
            val current = _preferences.value
            val updated = normalize(transform(current))
            if (updated == current) return
            _preferences.value = updated
            gen = writeGeneration.incrementAndGet()
            jsonToWrite = gson.toJson(updated)
        }

        val executor = persistExecutor
        if (executor != null) {
            executor.execute {
                if (writeGeneration.get() != gen) return@execute
                synchronized(diskLock) {
                    if (writeGeneration.get() != gen) return@synchronized
                    try {
                        storage.writeJson(jsonToWrite)
                    } catch (_: Exception) {
                    }
                }
            }
        } else {
            synchronized(diskLock) {
                try {
                    storage.writeJson(jsonToWrite)
                } catch (_: Exception) {
                }
            }
        }
    }

    override fun setCollapsePolicy(policy: CollapsePolicy) {
        updatePreferences { it.copy(collapsePolicy = policy) }
    }

    override fun setSortMode(mode: SortMode) {
        updatePreferences { it.copy(sortMode = mode) }
    }

    override fun setThemeMode(mode: ThemeMode) {
        updatePreferences { it.copy(themeMode = mode) }
    }

    override fun setAutoLockTimeout(timeout: AutoLockTimeout) {
        updatePreferences { it.copy(autoLockTimeout = timeout) }
    }

    override fun setLastActiveWorkspaceId(workspaceId: String) {
        val safeId = workspaceId.trim().ifBlank { "all" }
        updatePreferences { it.copy(lastActiveWorkspaceId = safeId) }
    }

    override fun setPrivacyMaskEnabled(enabled: Boolean) {
        updatePreferences { it.copy(privacyMaskEnabled = enabled) }
    }

    override fun recordBackupCompleted(timestampMs: Long, tokenCount: Int) {
        val safeTs = timestampMs.coerceAtLeast(1L)
        val safeCount = tokenCount.coerceAtLeast(0)
        updatePreferences {
            it.copy(
                lastBackupAtMillis = safeTs,
                lastBackupTokenCount = safeCount
            )
        }
    }

    override fun setGroupExpanded(workspaceId: String, issuerKey: String, expanded: Boolean) {
        val wsKey = workspaceId.trim().ifBlank { "all" }
        val normalizedKey = issuerKey.trim().lowercase(Locale.US)
        if (normalizedKey.isEmpty()) return

        updatePreferences { current ->
            val nextMap = current.expandedIssuerKeys.toMutableMap()
            val nextSet = (nextMap[wsKey] ?: emptySet()).toMutableSet()
            if (expanded) {
                nextSet.add(normalizedKey)
            } else {
                nextSet.remove(normalizedKey)
            }
            nextMap[wsKey] = nextSet.toSet()
            current.copy(expandedIssuerKeys = nextMap.toMap())
        }
    }

    override fun setWorkspaceExpandedKeys(workspaceId: String, issuerKeys: Set<String>) {
        val wsKey = workspaceId.trim().ifBlank { "all" }
        val normalizedKeys = issuerKeys
            .map { it.trim().lowercase(Locale.US) }
            .filter { it.isNotEmpty() }
            .toSet()

        updatePreferences { current ->
            val nextMap = current.expandedIssuerKeys.toMutableMap()
            nextMap[wsKey] = normalizedKeys
            current.copy(expandedIssuerKeys = nextMap.toMap())
        }
    }

    override fun clearAllPreferences() {
        synchronized(lock) {
            writeGeneration.incrementAndGet()
            _preferences.value = VaultPreferences()
        }
        synchronized(diskLock) {
            try {
                storage.clear()
            } catch (_: Exception) {
            }
        }
    }
}
