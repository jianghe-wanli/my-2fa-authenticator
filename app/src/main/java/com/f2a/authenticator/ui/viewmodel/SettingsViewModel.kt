package com.f2a.authenticator.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.AutoLockTimeout
import com.f2a.authenticator.data.model.CollapsePolicy
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.ThemeMode
import com.f2a.authenticator.data.model.VaultPreferences
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.di.AppContainer
import com.f2a.authenticator.security.BiometricHelper
import com.f2a.authenticator.security.BiometricStatus
import com.f2a.authenticator.security.PinConfigResult
import com.f2a.authenticator.security.SecurityLockManager
import com.f2a.authenticator.security.VaultHealthAnalyzer
import com.f2a.authenticator.ui.state.SettingsUiState
import com.f2a.authenticator.ui.state.TrashItemUi
import com.f2a.authenticator.utils.ClipboardGuard
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(
    application: Application,
    private val container: AppContainer
) : AndroidViewModel(application) {

    private val tokenRepository = container.tokenRepository
    private val preferencesRepository = container.preferencesRepository
    private val securityManager = container.securityLockManager
    private val clock = container.clock

    private val securityMetaFlow = MutableStateFlow(readSecurityMeta())

    val uiState: StateFlow<SettingsUiState> = combine(
        tokenRepository.workspaces,
        tokenRepository.tags,
        tokenRepository.tokens,
        tokenRepository.trashedTokens,
        preferencesRepository.preferences,
        securityMetaFlow
    ) { values ->
        @Suppress("UNCHECKED_CAST")
        val workspaces = values[0] as List<Workspace>
        @Suppress("UNCHECKED_CAST")
        val tags = values[1] as List<Tag>
        @Suppress("UNCHECKED_CAST")
        val tokens = values[2] as List<AuthToken>
        @Suppress("UNCHECKED_CAST")
        val trashed = values[3] as List<AuthToken>
        val prefs = values[4] as VaultPreferences
        val sec = values[5] as SecurityMeta

        val now = clock.currentTimeMillis()
        val retentionMs = 7L * 24 * 60 * 60 * 1000
        val dayMs = 24L * 60 * 60 * 1000
        val trashItems = trashed.map { token ->
            val delAt = token.deletedAt ?: now
            val expiresAt = delAt + retentionMs
            val remainingDays = (((expiresAt - now).coerceAtLeast(0L) + dayMs - 1L) / dayMs).toInt().coerceIn(0, 7)
            TrashItemUi(
                token = token,
                deletedAt = delAt,
                expiresAt = expiresAt,
                remainingDays = remainingDays
            )
        }.sortedByDescending { it.deletedAt }

        val countsByWs = tokens.groupingBy { it.workspaceId }.eachCount()
        val healthReport = VaultHealthAnalyzer.analyze(
            tokens = tokens,
            preferences = prefs,
            isDuressConfigured = sec.hasDuressPin,
            isBiometricEnabled = sec.biometricEnabled,
            nowMs = now,
            isFlagSecureEnabled = sec.flagSecureEnabled,
            clipboardClearSeconds = sec.clipboardClearSeconds
        )

        SettingsUiState(
            workspaces = workspaces,
            tags = tags,
            tokensCount = tokens.size,
            tokenCountByWorkspace = countsByWs,
            trashedItems = trashItems,
            maxAttempts = sec.maxAttempts,
            flagSecureEnabled = sec.flagSecureEnabled,
            clipboardClearSeconds = sec.clipboardClearSeconds,
            hasDuressPin = sec.hasDuressPin,
            biometricEnabled = sec.biometricEnabled,
            biometricStatus = sec.biometricStatus,
            themeMode = prefs.themeMode,
            collapsePolicy = prefs.collapsePolicy,
            autoLockTimeout = prefs.autoLockTimeout,
            privacyMaskEnabled = prefs.privacyMaskEnabled,
            lastBackupAtMillis = prefs.lastBackupAtMillis,
            healthReport = healthReport
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000L),
        initialValue = SettingsUiState()
    )

    private data class SecurityMeta(
        val maxAttempts: Int,
        val flagSecureEnabled: Boolean,
        val clipboardClearSeconds: Int,
        val hasDuressPin: Boolean,
        val biometricEnabled: Boolean,
        val biometricStatus: BiometricStatus
    )

    private fun readSecurityMeta(): SecurityMeta = SecurityMeta(
        maxAttempts = securityManager.getMaxAttempts(),
        flagSecureEnabled = securityManager.isFlagSecureEnabled(),
        clipboardClearSeconds = securityManager.getClipboardClearSeconds(),
        hasDuressPin = securityManager.hasDuressPin(),
        biometricEnabled = securityManager.isBiometricEnabled(),
        biometricStatus = try {
            BiometricHelper.checkAvailability(getApplication())
        } catch (_: Throwable) {
            BiometricStatus.UNSUPPORTED
        }
    )

    fun refreshSecurityMeta() {
        securityMetaFlow.value = readSecurityMeta()
    }

    fun setMaxAttempts(attempts: Int) {
        securityManager.setMaxAttempts(attempts)
        refreshSecurityMeta()
    }

    fun setFlagSecureEnabled(enabled: Boolean) {
        securityManager.setFlagSecureEnabled(enabled)
        refreshSecurityMeta()
    }

    fun setClipboardClearSeconds(seconds: Int) {
        securityManager.setClipboardClearSeconds(seconds)
        refreshSecurityMeta()
    }

    fun setBiometricEnabled(enabled: Boolean) {
        securityManager.setBiometricEnabled(enabled)
        refreshSecurityMeta()
    }

    fun setPrivacyMaskEnabled(enabled: Boolean) {
        preferencesRepository.setPrivacyMaskEnabled(enabled)
    }

    fun setThemeMode(mode: ThemeMode) {
        preferencesRepository.setThemeMode(mode)
    }

    fun setCollapsePolicy(policy: CollapsePolicy) {
        preferencesRepository.setCollapsePolicy(policy)
    }

    fun setAutoLockTimeout(timeout: AutoLockTimeout) {
        preferencesRepository.setAutoLockTimeout(timeout)
    }

    fun changeMasterPin(
        currentPin: String,
        newPin: String,
        onResult: (PinConfigResult) -> Unit
    ) {
        viewModelScope.launch {
            val res = securityManager.changeMasterPin(currentPin, newPin)
            if (res is PinConfigResult.AuthFailed &&
                (res.verifyResult is SecurityLockManager.VerifyResult.DuressTriggered ||
                    res.verifyResult is SecurityLockManager.VerifyResult.SelfDestructed)
            ) {
                wipeVaultOnDestruct()
            }
            refreshSecurityMeta()
            onResult(res)
        }
    }

    fun setDuressPin(
        currentMasterPin: String,
        duressPin: String,
        onResult: (PinConfigResult) -> Unit
    ) {
        viewModelScope.launch {
            val res = securityManager.setDuressPin(currentMasterPin, duressPin)
            if (res is PinConfigResult.AuthFailed &&
                (res.verifyResult is SecurityLockManager.VerifyResult.DuressTriggered ||
                    res.verifyResult is SecurityLockManager.VerifyResult.SelfDestructed)
            ) {
                wipeVaultOnDestruct()
            }
            refreshSecurityMeta()
            onResult(res)
        }
    }

    fun clearDuressPin(
        currentMasterPin: String,
        onResult: (PinConfigResult) -> Unit
    ) {
        viewModelScope.launch {
            val res = securityManager.clearDuressPin(currentMasterPin)
            if (res is PinConfigResult.AuthFailed &&
                (res.verifyResult is SecurityLockManager.VerifyResult.DuressTriggered ||
                    res.verifyResult is SecurityLockManager.VerifyResult.SelfDestructed)
            ) {
                wipeVaultOnDestruct()
            }
            refreshSecurityMeta()
            onResult(res)
        }
    }

    fun verifyAndClearAllTokens(
        pin: String,
        onResult: (SecurityLockManager.VerifyResult) -> Unit
    ) {
        viewModelScope.launch {
            val verify = securityManager.verifyPin(pin)
            when (verify) {
                is SecurityLockManager.VerifyResult.Success -> {
                    tokenRepository.clearAllTokens()
                }
                is SecurityLockManager.VerifyResult.DuressTriggered,
                is SecurityLockManager.VerifyResult.SelfDestructed -> {
                    wipeVaultOnDestruct()
                }
                else -> Unit
            }
            refreshSecurityMeta()
            onResult(verify)
        }
    }

    private suspend fun wipeVaultOnDestruct() {
        tokenRepository.wipeInMemoryState()
        preferencesRepository.clearAllPreferences()
        ClipboardGuard.clearNow(getApplication())
    }

    fun addWorkspace(name: String) {
        viewModelScope.launch {
            if (name.isNotBlank()) {
                tokenRepository.addWorkspace(Workspace(name = name.trim()))
            }
        }
    }

    fun renameWorkspace(workspaceId: String, newName: String) {
        viewModelScope.launch {
            if (newName.isNotBlank()) {
                tokenRepository.renameWorkspace(workspaceId, newName.trim())
            }
        }
    }

    fun deleteWorkspace(workspaceId: String) {
        viewModelScope.launch {
            tokenRepository.deleteWorkspace(workspaceId)
        }
    }

    fun addTag(name: String, colorHex: String) {
        viewModelScope.launch {
            if (name.isNotBlank()) {
                tokenRepository.addTag(Tag(name = name.trim(), colorHex = colorHex))
            }
        }
    }

    fun deleteTag(tagId: String) {
        viewModelScope.launch {
            tokenRepository.deleteTag(tagId)
        }
    }

    fun restoreTrashToken(tokenId: String) {
        viewModelScope.launch {
            tokenRepository.restoreToken(tokenId)
        }
    }

    fun permanentlyDeleteTrashToken(tokenId: String) {
        viewModelScope.launch {
            tokenRepository.permanentlyDeleteToken(tokenId)
        }
    }

    fun emptyTrash() {
        viewModelScope.launch {
            tokenRepository.emptyTrash()
        }
    }

    class Factory(
        private val application: Application,
        private val container: AppContainer
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return SettingsViewModel(application, container) as T
        }
    }
}
