package com.f2a.authenticator.ui.state

import androidx.compose.runtime.Immutable
import com.f2a.authenticator.data.model.AutoLockTimeout
import com.f2a.authenticator.data.model.CollapsePolicy
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.ThemeMode
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.BiometricStatus
import com.f2a.authenticator.security.VaultHealthReport

@Immutable
data class SettingsUiState(
    val workspaces: List<Workspace> = emptyList(),
    val tags: List<Tag> = emptyList(),
    val tokensCount: Int = 0,
    val tokenCountByWorkspace: Map<String, Int> = emptyMap(),
    val trashedItems: List<TrashItemUi> = emptyList(),
    val maxAttempts: Int = 5,
    val flagSecureEnabled: Boolean = true,
    val clipboardClearSeconds: Int = 45,
    val hasDuressPin: Boolean = false,
    val biometricEnabled: Boolean = false,
    val biometricStatus: BiometricStatus = BiometricStatus.UNSUPPORTED,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val collapsePolicy: CollapsePolicy = CollapsePolicy.COLLAPSE_ALL,
    val autoLockTimeout: AutoLockTimeout = AutoLockTimeout.SECONDS_30,
    val privacyMaskEnabled: Boolean = false,
    val lastBackupAtMillis: Long? = null,
    val healthReport: VaultHealthReport? = null
)
