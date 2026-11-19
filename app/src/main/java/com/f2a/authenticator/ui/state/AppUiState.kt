package com.f2a.authenticator.ui.state

import androidx.compose.runtime.Immutable
import com.f2a.authenticator.data.model.ThemeMode

@Immutable
data class VaultAuthState(
    val isPinConfigured: Boolean = false,
    val isUnlocked: Boolean = false,
    val isBiometricEnabled: Boolean = false,
    val isBiometricAvailable: Boolean = false,
    val remainingAttempts: Int = 5,
    val lockoutSeconds: Long = 0L,
    val missingPinAnomaly: Boolean = false
)

sealed interface AppRoute {
    data object Home : AppRoute
    data object Scan : AppRoute
    data object Settings : AppRoute
    data class Detail(val tokenId: String) : AppRoute
}

sealed interface ActiveModal {
    data object None : ActiveModal
    data object AddToken : ActiveModal
    data object Backup : ActiveModal
    data object BatchExport : ActiveModal
}

@Immutable
data class AppShellUiState(
    val authState: VaultAuthState = VaultAuthState(),
    val route: AppRoute = AppRoute.Home,
    val activeModal: ActiveModal = ActiveModal.None,
    val activeWorkspaceId: String = "all",
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val flagSecureEnabled: Boolean = true,
    val snackbarMessage: String? = null,
    val vaultLoadCorrupted: Boolean = false,
    val missingPinRecoveredNotice: Boolean = false,
    val selfDestructed: Boolean = false
)
