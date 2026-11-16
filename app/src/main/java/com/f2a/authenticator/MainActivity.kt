package com.f2a.authenticator

import android.graphics.Color
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import com.f2a.authenticator.data.model.ThemeMode
import com.f2a.authenticator.di.AppContainer
import com.f2a.authenticator.ui.screens.detail.TokenDetailScreen
import com.f2a.authenticator.ui.screens.dialogs.AddTokenDialog
import com.f2a.authenticator.ui.screens.dialogs.BackupDialog
import com.f2a.authenticator.ui.screens.dialogs.BatchExportDialog
import com.f2a.authenticator.ui.screens.home.MainHomeScreen
import com.f2a.authenticator.ui.screens.lock.SecurityLockScreen
import com.f2a.authenticator.ui.screens.scan.CameraScanScreen
import com.f2a.authenticator.ui.screens.settings.SettingsScreen
import com.f2a.authenticator.ui.state.ActiveModal
import com.f2a.authenticator.ui.state.AppRoute
import com.f2a.authenticator.ui.theme.Motion
import com.f2a.authenticator.ui.theme.My2FATheme
import com.f2a.authenticator.ui.viewmodel.AppViewModel
import com.f2a.authenticator.ui.viewmodel.BackupViewModel
import com.f2a.authenticator.ui.viewmodel.DetailViewModel
import com.f2a.authenticator.ui.viewmodel.HomeViewModel
import com.f2a.authenticator.ui.viewmodel.SettingsViewModel
import kotlinx.coroutines.delay

class MainActivity : FragmentActivity() {

    private lateinit var appContainer: AppContainer
    private lateinit var appViewModel: AppViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        appContainer = (application as My2FAApplication).container
        appViewModel = ViewModelProvider(
            this,
            AppViewModel.Factory(application, appContainer)
        )[AppViewModel::class.java]

        // 初始锁屏态强制开启 FLAG_SECURE
        applyFlagSecure(true)

        setContent {
            val shellState by appViewModel.uiState.collectAsState()
            val systemDark = isSystemInDarkTheme()
            val isDark = when (shellState.themeMode) {
                ThemeMode.DARK -> true
                ThemeMode.LIGHT -> false
                ThemeMode.SYSTEM -> systemDark
            }

            DisposableEffect(isDark) {
                enableEdgeToEdge(
                    statusBarStyle = if (isDark) {
                        SystemBarStyle.dark(Color.TRANSPARENT)
                    } else {
                        SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                    },
                    navigationBarStyle = if (isDark) {
                        SystemBarStyle.dark(Color.TRANSPARENT)
                    } else {
                        SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                    }
                )
                onDispose {}
            }

            // 【安全红线】锁屏期间始终强制开启 FLAG_SECURE；解锁后同步用户设置
            DisposableEffect(shellState.authState.isUnlocked, shellState.flagSecureEnabled) {
                val shouldSecure = !shellState.authState.isUnlocked || shellState.flagSecureEnabled
                applyFlagSecure(shouldSecure)
                onDispose {}
            }

            My2FATheme(themeMode = shellState.themeMode) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    if (!shellState.authState.isUnlocked) {
                        SecurityLockScreen(
                            authState = shellState.authState,
                            onSetupPin = { pin, cb -> appViewModel.setupPinAndUnlock(pin, cb) },
                            onVerifyPin = { pin, cb -> appViewModel.verifyPinAndUnlock(pin, cb) },
                            onBiometricUnlock = { activity, onErr ->
                                appViewModel.authenticateWithBiometric(activity, onErr)
                            },
                            onRefreshLockout = { appViewModel.refreshLockoutSeconds() }
                        )
                    } else {
                        UnlockedAppShell(
                            container = appContainer,
                            appViewModel = appViewModel,
                            onSelfDestructFinish = { finishAndRemoveTask() }
                        )
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (::appViewModel.isInitialized) {
            appViewModel.onAppResumed()
        }
    }

    private fun applyFlagSecure(enable: Boolean) {
        if (enable) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

@Composable
private fun UnlockedAppShell(
    container: AppContainer,
    appViewModel: AppViewModel,
    onSelfDestructFinish: () -> Unit
) {
    val shellState by appViewModel.uiState.collectAsState()

    val application = androidx.compose.ui.platform.LocalContext.current.applicationContext as android.app.Application
    val homeViewModel: HomeViewModel = viewModel(
        factory = HomeViewModel.Factory(
            tokenRepository = container.tokenRepository,
            preferencesRepository = container.preferencesRepository,
            securityManager = container.securityLockManager
        )
    )
    val detailViewModel: DetailViewModel = viewModel(
        factory = DetailViewModel.Factory(
            tokenRepository = container.tokenRepository,
            securityManager = container.securityLockManager
        )
    )
    val backupViewModel: BackupViewModel = viewModel(
        factory = BackupViewModel.Factory(
            tokenRepository = container.tokenRepository,
            securityManager = container.securityLockManager,
            preferencesRepository = container.preferencesRepository
        )
    )
    val settingsViewModel: SettingsViewModel = viewModel(
        factory = SettingsViewModel.Factory(application, container)
    )

    val homeState by homeViewModel.uiState.collectAsState()
    val settingsState by settingsViewModel.uiState.collectAsState()

    // V2-UI-04：高频 100ms 时钟仅由 State 容器持有，通过 lambda 传入叶子组件 OtpTicker，父树 0 重组
    val nowMsState = remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            nowMsState.longValue = System.currentTimeMillis()
            delay(100L)
        }
    }
    val nowMsProvider: () -> Long = remember { { nowMsState.longValue } }

    AnimatedContent(
        targetState = shellState.route,
        transitionSpec = {
            (fadeIn(tween(250, easing = Motion.EaseStandard)) +
                slideInHorizontally(tween(250, easing = Motion.EaseStandard)) { full -> full / 16 }) togetherWith
                (fadeOut(tween(250, easing = Motion.EaseStandard)) +
                    slideOutHorizontally(tween(250, easing = Motion.EaseStandard)) { full -> -full / 16 })
        },
        label = "page_transition"
    ) { target ->
        when (target) {
            AppRoute.Scan -> {
                CameraScanScreen(
                    currentActiveWorkspaceId = shellState.activeWorkspaceId,
                    allWorkspaces = homeState.workspaces,
                    allTags = homeState.tags,
                    onSuppressNextBackgroundLock = { appViewModel.suppressNextBackgroundLock() },
                    onBack = { appViewModel.navigateTo(AppRoute.Home) },
                    onManualInputClick = {
                        appViewModel.navigateTo(AppRoute.Home)
                        appViewModel.openModal(ActiveModal.AddToken)
                    },
                    onTokenScanned = { token ->
                        appViewModel.addSingleTokenDedup(token)
                        appViewModel.navigateTo(AppRoute.Home)
                    },
                    onBatchTokensScanned = { batch, batchNotice ->
                        appViewModel.addBatchTokensDedup(batch, batchNotice)
                        appViewModel.navigateTo(AppRoute.Home)
                    }
                )
            }

            AppRoute.Settings -> {
                SettingsScreen(
                    uiState = settingsState,
                    onBack = {
                        homeViewModel.refreshClipboardSeconds()
                        appViewModel.navigateTo(AppRoute.Home)
                    },
                    onLockNow = { appViewModel.lockNow() },
                    onOpenBackup = { appViewModel.openModal(ActiveModal.Backup) },
                    onOpenBatchExport = { appViewModel.openModal(ActiveModal.BatchExport) },
                    onSetMaxAttempts = { settingsViewModel.setMaxAttempts(it) },
                    onSetFlagSecure = { enabled ->
                        settingsViewModel.setFlagSecureEnabled(enabled)
                        appViewModel.setFlagSecureEnabled(enabled)
                    },
                    onSetClipboardClearSeconds = { sec ->
                        settingsViewModel.setClipboardClearSeconds(sec)
                        homeViewModel.refreshClipboardSeconds()
                    },
                    onSetBiometricEnabled = { enabled ->
                        settingsViewModel.setBiometricEnabled(enabled)
                        appViewModel.refreshAuthState()
                    },
                    onSetThemeMode = { settingsViewModel.setThemeMode(it) },
                    onSetCollapsePolicy = { settingsViewModel.setCollapsePolicy(it) },
                    onSetAutoLockTimeout = { settingsViewModel.setAutoLockTimeout(it) },
                    onChangeMasterPin = { cur, next, cb -> settingsViewModel.changeMasterPin(cur, next, cb) },
                    onSetDuressPin = { master, duress, cb -> settingsViewModel.setDuressPin(master, duress, cb) },
                    onClearDuressPin = { master, cb -> settingsViewModel.clearDuressPin(master, cb) },
                    onVerifyAndClearAll = { pin, cb -> settingsViewModel.verifyAndClearAllTokens(pin, cb) },
                    onSelfDestructed = {
                        appViewModel.lockNow()
                        onSelfDestructFinish()
                    },
                    onExecuteSelfDestruct = { appViewModel.executeSelfDestruct(onSelfDestructFinish) },
                    onAddWorkspace = { settingsViewModel.addWorkspace(it) },
                    onRenameWorkspace = { id, name -> settingsViewModel.renameWorkspace(id, name) },
                    onDeleteWorkspace = { settingsViewModel.deleteWorkspace(it) },
                    onAddTag = { name, hex -> settingsViewModel.addTag(name, hex) },
                    onDeleteTag = { settingsViewModel.deleteTag(it) },
                    onRestoreTrashToken = { settingsViewModel.restoreTrashToken(it) },
                    onPermanentDeleteTrashToken = { settingsViewModel.permanentlyDeleteTrashToken(it) },
                    onEmptyTrash = { settingsViewModel.emptyTrash() }
                )
            }

            is AppRoute.Detail -> {
                val initialToken = remember(target.tokenId) {
                    detailViewModel.currentTokenSnapshot(target.tokenId)
                }
                val detailToken by detailViewModel.observeToken(target.tokenId).collectAsState(initial = initialToken)
                val tags by detailViewModel.allTags.collectAsState()
                val workspaces by detailViewModel.allWorkspaces.collectAsState()

                LaunchedEffect(detailToken) {
                    if (detailToken == null) {
                        appViewModel.navigateTo(AppRoute.Home)
                    }
                }

                detailToken?.let { token ->
                    TokenDetailScreen(
                        token = token,
                        allTags = tags,
                        allWorkspaces = workspaces,
                        clipboardClearSeconds = detailViewModel.getClipboardClearSeconds(),
                        nowMsProvider = nowMsProvider,
                        onBack = { appViewModel.navigateTo(AppRoute.Home) },
                        onUpdateToken = { updated -> detailViewModel.updateToken(updated) },
                        onAdvanceHotp = { t -> detailViewModel.advanceHotp(t) },
                        onRecordTokenUsed = { id -> detailViewModel.recordTokenUsed(id) },
                        onDeleteToTrash = { id ->
                            detailViewModel.softDeleteToken(id) {
                                appViewModel.showNotice("已移入回收站（7 天内可恢复）")
                                appViewModel.navigateTo(AppRoute.Home)
                            }
                        },
                        onReimportClick = {
                            appViewModel.navigateTo(AppRoute.Home)
                            appViewModel.openModal(ActiveModal.AddToken)
                        }
                    )
                }
            }

            AppRoute.Home -> {
                MainHomeScreen(
                    uiState = homeState,
                    nowMsProvider = nowMsProvider,
                    onSelectWorkspace = { wsId ->
                        homeViewModel.setActiveWorkspaceId(wsId)
                        appViewModel.setActiveWorkspaceId(wsId)
                    },
                    onSetSearchExpanded = { homeViewModel.setSearchExpanded(it) },
                    onSearchQueryChange = { homeViewModel.setSearchQuery(it) },
                    onSelectTagFilter = { homeViewModel.selectTagFilter(it) },
                    onClearFilters = { homeViewModel.clearFilters() },
                    onToggleExpandGroup = { homeViewModel.toggleGroupExpanded(it) },
                    onToggleExpandAll = { homeViewModel.toggleExpandAll() },
                    onSelectSortMode = { homeViewModel.setSortMode(it) },
                    onJumpToIssuer = { key -> homeViewModel.expandAndFindIndex(key) },
                    onTogglePin = { homeViewModel.togglePin(it) },
                    onSoftDeleteToken = { homeViewModel.softDeleteToken(it) },
                    onAdvanceHotp = { homeViewModel.advanceHotp(it) },
                    onRecordTokenUsed = { homeViewModel.recordTokenUsed(it) },
                    onAddTag = { name, hex -> homeViewModel.addTag(name, hex) },
                    onDeleteTag = { homeViewModel.deleteTag(it) },
                    onOpenAddDialog = { appViewModel.openModal(ActiveModal.AddToken) },
                    onOpenScanScreen = { appViewModel.navigateTo(AppRoute.Scan) },
                    onOpenSettingsScreen = {
                        settingsViewModel.refreshSecurityMeta()
                        appViewModel.navigateTo(AppRoute.Settings)
                    },
                    onLockNow = { appViewModel.lockNow() },
                    onTokenClick = { token -> appViewModel.navigateTo(AppRoute.Detail(token.id)) },
                    importNotice = shellState.snackbarMessage,
                    onImportNoticeShown = { appViewModel.consumeSnackbar() }
                )
            }
        }
    }

    when (shellState.activeModal) {
        ActiveModal.None -> Unit
        ActiveModal.AddToken -> {
            AddTokenDialog(
                workspaces = homeState.workspaces,
                tags = homeState.tags,
                activeWorkspaceId = shellState.activeWorkspaceId,
                onDismiss = { appViewModel.closeModal() },
                onConfirm = { newToken ->
                    appViewModel.addSingleTokenDedup(newToken)
                    appViewModel.closeModal()
                },
                onBatchConfirm = { batch ->
                    appViewModel.addBatchTokensDedup(batch)
                    appViewModel.closeModal()
                },
                onOpenScan = {
                    appViewModel.closeModal()
                    appViewModel.navigateTo(AppRoute.Scan)
                }
            )
        }
        ActiveModal.Backup -> {
            BackupDialog(
                viewModel = backupViewModel,
                onSuppressNextBackgroundLock = { appViewModel.suppressNextBackgroundLock() },
                onDismiss = { appViewModel.closeModal() }
            )
        }
        ActiveModal.BatchExport -> {
            BatchExportDialog(
                viewModel = backupViewModel,
                onSelfDestructed = {
                    appViewModel.lockNow()
                    onSelfDestructFinish()
                },
                onDismiss = { appViewModel.closeModal() }
            )
        }
    }
}
