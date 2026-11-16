package com.f2a.authenticator.data.local

import com.f2a.authenticator.data.model.AutoLockTimeout
import com.f2a.authenticator.data.model.CollapsePolicy
import com.f2a.authenticator.data.model.SortMode
import com.f2a.authenticator.data.model.ThemeMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultPreferencesStoreTest {

    private class InMemoryPreferencesStorage(
        var json: String? = null
    ) : PreferencesStorage {
        override fun readJson(): String? = json
        override fun writeJson(json: String) {
            this.json = json
        }
        override fun clear() {
            this.json = null
        }
    }

    @Test
    fun defaults_collapseAllAndExpectedInitialPreferences() {
        val store = VaultPreferencesStore(InMemoryPreferencesStorage())
        val prefs = store.preferences.value
        assertEquals(CollapsePolicy.COLLAPSE_ALL, prefs.collapsePolicy)
        assertEquals(SortMode.PINNED_AND_COUNT, prefs.sortMode)
        assertEquals(ThemeMode.SYSTEM, prefs.themeMode)
        assertEquals(AutoLockTimeout.SECONDS_30, prefs.autoLockTimeout)
        assertTrue(prefs.expandedIssuerKeys.isEmpty())
        assertEquals("all", prefs.lastActiveWorkspaceId)
    }

    @Test
    fun expandedIssuerKeys_isolatedByWorkspace_andPersistedAcrossReload() {
        val storage = InMemoryPreferencesStorage()
        val store = VaultPreferencesStore(storage)

        store.setGroupExpanded("workspace_personal", "GitHub", true)
        store.setGroupExpanded("workspace_personal", "Google", true)
        store.setGroupExpanded("workspace_work", "GitLab", true)
        store.setGroupExpanded("workspace_personal", "Google", false)

        val current = store.preferences.value.expandedIssuerKeys
        assertEquals(setOf("github"), current["workspace_personal"])
        assertEquals(setOf("gitlab"), current["workspace_work"])

        store.setWorkspaceExpandedKeys("workspace_work", setOf("Jira", "Slack"))

        // 重新实例化模拟进程重启
        val reloaded = VaultPreferencesStore(storage)
        val reloadedMap = reloaded.preferences.value.expandedIssuerKeys
        assertEquals(setOf("github"), reloadedMap["workspace_personal"])
        assertEquals(setOf("jira", "slack"), reloadedMap["workspace_work"])
    }

    @Test
    fun policySortThemeTimeoutAndActiveWorkspace_persistedAcrossReload() {
        val storage = InMemoryPreferencesStorage()
        val store = VaultPreferencesStore(storage)

        store.setCollapsePolicy(CollapsePolicy.REMEMBER_LAST)
        store.setSortMode(SortMode.ALPHABETICAL_AZ)
        store.setThemeMode(ThemeMode.LIGHT)
        store.setAutoLockTimeout(AutoLockTimeout.SECONDS_300)
        store.setLastActiveWorkspaceId("workspace_devops")

        val reloaded = VaultPreferencesStore(storage).preferences.value
        assertEquals(CollapsePolicy.REMEMBER_LAST, reloaded.collapsePolicy)
        assertEquals(SortMode.ALPHABETICAL_AZ, reloaded.sortMode)
        assertEquals(ThemeMode.LIGHT, reloaded.themeMode)
        assertEquals(AutoLockTimeout.SECONDS_300, reloaded.autoLockTimeout)
        assertEquals("workspace_devops", reloaded.lastActiveWorkspaceId)

        store.clearAllPreferences()
        assertEquals(CollapsePolicy.COLLAPSE_ALL, store.preferences.value.collapsePolicy)
        assertEquals(null, storage.json)
    }

    @Test
    fun corruptOrPartialJson_safelyNormalizedWithoutNpe() {
        val storage = InMemoryPreferencesStorage(
            json = """{"collapsePolicy":"UNKNOWN_FUTURE","expandedIssuerKeys":{"all":["GitHub",null]}}"""
        )
        val store = VaultPreferencesStore(storage)
        val prefs = store.preferences.value
        assertEquals(CollapsePolicy.COLLAPSE_ALL, prefs.collapsePolicy)
        assertEquals(SortMode.PINNED_AND_COUNT, prefs.sortMode)
        assertEquals(ThemeMode.SYSTEM, prefs.themeMode)
        assertEquals(AutoLockTimeout.SECONDS_30, prefs.autoLockTimeout)
        assertEquals(setOf("github"), prefs.expandedIssuerKeys["all"])
        assertEquals("all", prefs.lastActiveWorkspaceId)
    }
}
