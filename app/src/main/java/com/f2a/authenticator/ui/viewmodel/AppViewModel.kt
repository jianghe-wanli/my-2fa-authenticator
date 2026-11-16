package com.f2a.authenticator.ui.viewmodel

import android.app.Application
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.ThemeMode
import com.f2a.authenticator.di.AppContainer
import com.f2a.authenticator.security.BiometricHelper
import com.f2a.authenticator.security.BiometricStatus
import com.f2a.authenticator.security.PinConfigResult
import com.f2a.authenticator.security.SecurityLockManager
import com.f2a.authenticator.ui.state.ActiveModal
import com.f2a.authenticator.ui.state.AppRoute
import com.f2a.authenticator.ui.state.AppShellUiState
import com.f2a.authenticator.ui.state.VaultAuthState
import com.f2a.authenticator.utils.ClipboardGuard
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class AppViewModel(
    application: Application,
    private val container: AppContainer
) : AndroidViewModel(application) {

    private val tokenRepository = container.tokenRepository
    private val preferencesRepository = container.preferencesRepository
    private val securityManager = container.securityLockManager
    private val backgroundLockMonitor = container.backgroundLockMonitor

    // 【安全红线】isUnlocked 严禁写入 SavedStateHandle / SharedPreferences / 文件，仅驻留内存。
    private val isUnlockedFlow = MutableStateFlow(false)
    private val authMetaFlow = MutableStateFlow(readAuthMeta())
    private val routeFlow = MutableStateFlow<AppRoute>(AppRoute.Home)
    private val activeModalFlow = MutableStateFlow<ActiveModal>(ActiveModal.None)
    private val activeWorkspaceIdFlow = MutableStateFlow(
        preferencesRepository.preferences.value.lastActiveWorkspaceId.ifBlank { "all" }
    )
    private val flagSecureFlow = MutableStateFlow(securityManager.isFlagSecureEnabled())
    private val snackbarMessageFlow = MutableStateFlow<String?>(null)

    private val authStateFlow = combine(isUnlockedFlow, authMetaFlow) { unlocked, meta ->
        meta.copy(isUnlocked = unlocked)
    }

    val uiState: StateFlow<AppShellUiState> = combine(
        authStateFlow,
        routeFlow,
        activeModalFlow,
        activeWorkspaceIdFlow,
        preferencesRepository.preferences,
        flagSecureFlow,
        snackbarMessageFlow,
        tokenRepository.workspaces
    ) { values ->
        val auth = values[0] as VaultAuthState
        val route = values[1] as AppRoute
        val modal = values[2] as ActiveModal
        val activeWs = values[3] as String
        val prefs = values[4] as com.f2a.authenticator.data.model.VaultPreferences
        val flagSecure = values[5] as Boolean
        val snackbar = values[6] as String?
        @Suppress("UNCHECKED_CAST")
        val workspaces = values[7] as List<com.f2a.authenticator.data.model.Workspace>
        val resolvedActiveWs = if (activeWs != "all" && workspaces.isNotEmpty() && workspaces.none { it.id == activeWs }) {
            "all"
        } else {
            activeWs
        }
        AppShellUiState(
            authState = auth,
            route = route,
            activeModal = modal,
            activeWorkspaceId = resolvedActiveWs,
            themeMode = prefs.themeMode,
            flagSecureEnabled = flagSecure,
            snackbarMessage = snackbar
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000L),
        initialValue = AppShellUiState(
            authState = readAuthMeta().copy(isUnlocked = false),
            themeMode = preferencesRepository.preferences.value.themeMode,
            flagSecureEnabled = flagSecureFlow.value
        )
    )

    private fun readAuthMeta(): VaultAuthState {
        val ctx = getApplication<Application>()
        val isPinConfigured = securityManager.isPinConfigured()
        val bioAvailable = BiometricHelper.checkAvailability(ctx) == BiometricStatus.AVAILABLE
        val missingPinAnomaly = securityManager.isPinMissingAnomaly(tokenRepository.hasStoredEncryptedTokens())
        return VaultAuthState(
            isPinConfigured = isPinConfigured,
            isUnlocked = isUnlockedFlow.value,
            isBiometricEnabled = securityManager.isBiometricEnabled(),
            isBiometricAvailable = bioAvailable,
            remainingAttempts = securityManager.getRemainingAttempts(),
            lockoutSeconds = securityManager.getLockoutRemainingSeconds(),
            missingPinAnomaly = missingPinAnomaly
        )
    }

    fun refreshAuthState() {
        authMetaFlow.value = readAuthMeta()
        flagSecureFlow.value = securityManager.isFlagSecureEnabled()
    }

    fun refreshLockoutSeconds(): Long {
        val sec = securityManager.getLockoutRemainingSeconds()
        authMetaFlow.value = readAuthMeta().copy(lockoutSeconds = sec)
        return sec
    }

    fun setupPinAndUnlock(pin: String, onResult: (PinConfigResult) -> Unit) {
        viewModelScope.launch {
            val result = securityManager.setupPin(pin)
            if (result is PinConfigResult.Ok) {
                tokenRepository.unlockAndLoad()
                backgroundLockMonitor.resetBackgroundTimer()
                isUnlockedFlow.value = true
                refreshAuthState()
            } else {
                refreshAuthState()
            }
            onResult(result)
        }
    }

    fun verifyPinAndUnlock(pin: String, onResult: (SecurityLockManager.VerifyResult) -> Unit) {
        viewModelScope.launch {
            val result = securityManager.verifyPin(pin)
            when (result) {
                is SecurityLockManager.VerifyResult.Success -> {
                    tokenRepository.unlockAndLoad()
                    backgroundLockMonitor.resetBackgroundTimer()
                    isUnlockedFlow.value = true
                }
                is SecurityLockManager.VerifyResult.DuressTriggered -> {
                    // 【安全红线】先同步清空内存密钥与 StateFlow 并阻断回写，再解锁空库/诱饵态
                    tokenRepository.wipeInMemoryState()
                    backgroundLockMonitor.resetBackgroundTimer()
                    isUnlockedFlow.value = true
                }
                else -> Unit
            }
            refreshAuthState()
            onResult(result)
        }
    }

    fun authenticateWithBiometric(
        activity: FragmentActivity,
        onError: (String) -> Unit
    ) {
        if (!securityManager.isPinConfigured() || !securityManager.isBiometricEnabled()) return
        BiometricHelper.authenticate(
            activity = activity,
            onSuccess = {
                viewModelScope.launch {
                    tokenRepository.unlockAndLoad()
                    backgroundLockMonitor.resetBackgroundTimer()
                    isUnlockedFlow.value = true
                    refreshAuthState()
                }
            },
            onError = { _, message -> onError(message) },
            onCancelled = {}
        )
    }

    fun lockNow() {
        isUnlockedFlow.value = false
        routeFlow.value = AppRoute.Home
        activeModalFlow.value = ActiveModal.None
        tokenRepository.lockInMemory()
        refreshAuthState()
    }

    fun onAppResumed() {
        ClipboardGuard.clearIfExpiredOnResume(getApplication())
        if (isUnlockedFlow.value) {
            val timeout = preferencesRepository.preferences.value.autoLockTimeout
            if (backgroundLockMonitor.checkAndConsumeShouldLock(timeout)) {
                lockNow()
                return
            }
        }
        refreshAuthState()
    }

    fun suppressNextBackgroundLock() {
        backgroundLockMonitor.suppressNextBackgroundLock()
    }

    fun navigateTo(route: AppRoute) {
        routeFlow.value = route
    }

    fun openModal(modal: ActiveModal) {
        activeModalFlow.value = modal
    }

    fun closeModal() {
        activeModalFlow.value = ActiveModal.None
    }

    fun setActiveWorkspaceId(workspaceId: String) {
        activeWorkspaceIdFlow.value = workspaceId
        preferencesRepository.setLastActiveWorkspaceId(workspaceId)
    }

    fun setFlagSecureEnabled(enabled: Boolean) {
        flagSecureFlow.value = enabled
    }

    fun consumeSnackbar() {
        snackbarMessageFlow.value = null
    }

    fun showNotice(message: String) {
        snackbarMessageFlow.value = message
    }

    fun addSingleTokenDedup(token: AuthToken) {
        viewModelScope.launch {
            val (added, _) = tokenRepository.addTokensDedup(listOf(token))
            snackbarMessageFlow.value = if (added > 0) {
                "已添加：${token.issuer}"
            } else {
                "凭据已存在，已跳过重复导入"
            }
        }
    }

    fun addBatchTokensDedup(tokens: List<AuthToken>, batchNotice: String? = null) {
        viewModelScope.launch {
            val (added, skipped) = tokenRepository.addTokensDedup(tokens)
            val summary = if (skipped > 0) {
                "成功导入 $added 个凭据，跳过重复 $skipped 个"
            } else {
                "成功导入 $added 个凭据"
            }
            snackbarMessageFlow.value = if (!batchNotice.isNullOrBlank()) {
                "$batchNotice · $summary"
            } else {
                summary
            }
        }
    }

    fun executeSelfDestruct(onComplete: () -> Unit) {
        viewModelScope.launch {
            tokenRepository.wipeInMemoryState()
            preferencesRepository.clearAllPreferences()
            securityManager.executePermanentSelfDestruct(silent = false)
            isUnlockedFlow.value = false
            onComplete()
        }
    }

    class Factory(
        private val application: Application,
        private val container: AppContainer
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return AppViewModel(application, container) as T
        }
    }
}
