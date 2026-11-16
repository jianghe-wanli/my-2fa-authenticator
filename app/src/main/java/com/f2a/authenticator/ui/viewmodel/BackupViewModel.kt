package com.f2a.authenticator.ui.viewmodel

import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.f2a.authenticator.crypto.BackupExportResult
import com.f2a.authenticator.crypto.BackupImportResult
import com.f2a.authenticator.crypto.BackupManager
import com.f2a.authenticator.data.local.TokenVaultRepository
import com.f2a.authenticator.data.local.VaultPreferencesRepository
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.BackupPayload
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.SecurityLockManager
import com.f2a.authenticator.totp.GoogleMigrationEncoder
import com.f2a.authenticator.totp.MigrationExportPlan
import com.f2a.authenticator.ui.utils.QrBitmapRenderer
import com.f2a.authenticator.utils.SecureClipboard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets

class BackupViewModel(
    private val tokenRepository: TokenVaultRepository,
    private val securityManager: SecurityLockManager,
    private val preferencesRepository: VaultPreferencesRepository? = null
) : ViewModel() {

    val workspaces: StateFlow<List<Workspace>> = tokenRepository.workspaces
    val tags: StateFlow<List<Tag>> = tokenRepository.tags
    val tokens: StateFlow<List<AuthToken>> = tokenRepository.tokens

    private val _isBusy = MutableStateFlow(false)
    val isBusy: StateFlow<Boolean> = _isBusy.asStateFlow()

    private val _statusMessage = MutableStateFlow("")
    val statusMessage: StateFlow<String> = _statusMessage.asStateFlow()

    private val _statusIsError = MutableStateFlow(false)
    val statusIsError: StateFlow<Boolean> = _statusIsError.asStateFlow()

    fun clearStatus() {
        _statusMessage.value = ""
        _statusIsError.value = false
    }

    fun getClipboardClearSeconds(): Int = securityManager.getClipboardClearSeconds()

    fun exportToClipboard(
        context: Context,
        passphrase: String,
        onSnackbar: (String) -> Unit
    ) {
        if (_isBusy.value) return
        val payload = BackupPayload(
            workspaces = workspaces.value,
            tags = tags.value,
            tokens = tokens.value
        )
        viewModelScope.launch {
            _isBusy.value = true
            try {
                val res = withContext(Dispatchers.Default) {
                    BackupManager.exportEncryptedBackup(payload, passphrase)
                }
                when (res) {
                    is BackupExportResult.Ok -> {
                        val clearSec = securityManager.getClipboardClearSeconds().let { if (it <= 0) 30 else it.coerceAtMost(30) }
                        SecureClipboard.copySensitive(context, res.encodedBase64, clearSec)
                        val skipNote = if (res.skippedInvalidCount > 0) "（已跳过 ${res.skippedInvalidCount} 条损坏或回收站凭据）" else ""
                        _statusIsError.value = false
                        _statusMessage.value = "已加密导出 ${res.exportedCount} 个凭据并复制到剪贴板$skipNote。备份包等同于明文种子，请妥善保管。"
                        onSnackbar("已生成加密备份并复制到剪贴板")
                    }
                    is BackupExportResult.Error -> {
                        _statusIsError.value = true
                        _statusMessage.value = "⚠ ${res.message}"
                    }
                }
            } finally {
                _isBusy.value = false
            }
        }
    }

    fun exportToSafUri(
        context: Context,
        uri: Uri,
        passphrase: String,
        onSnackbar: (String) -> Unit
    ) {
        if (_isBusy.value) return
        val payload = BackupPayload(
            workspaces = workspaces.value,
            tags = tags.value,
            tokens = tokens.value
        )
        viewModelScope.launch {
            _isBusy.value = true
            try {
                val res = withContext(Dispatchers.Default) {
                    BackupManager.exportEncryptedBackup(payload, passphrase)
                }
                when (res) {
                    is BackupExportResult.Ok -> {
                        val writeOk = withContext(Dispatchers.IO) {
                            try {
                                val os = context.contentResolver.openOutputStream(uri) ?: return@withContext false
                                os.use { stream ->
                                    stream.write(res.encodedBase64.toByteArray(StandardCharsets.UTF_8))
                                    stream.flush()
                                }
                                true
                            } catch (_: Exception) {
                                false
                            }
                        }
                        if (writeOk) {
                            _statusIsError.value = false
                            _statusMessage.value = "已导出 ${res.exportedCount} 个凭据至安全备份文件。"
                            onSnackbar("备份文件保存成功")
                        } else {
                            _statusIsError.value = true
                            _statusMessage.value = "⚠ 写入备份文件失败"
                        }
                    }
                    is BackupExportResult.Error -> {
                        _statusIsError.value = true
                        _statusMessage.value = "⚠ ${res.message}"
                    }
                }
            } finally {
                _isBusy.value = false
            }
        }
    }

    fun importFromString(
        rawCiphertext: String,
        passphrase: String,
        onSnackbar: (String) -> Unit
    ) {
        if (_isBusy.value) return
        viewModelScope.launch {
            _isBusy.value = true
            try {
                performImport(rawCiphertext, passphrase, onSnackbar)
            } finally {
                _isBusy.value = false
            }
        }
    }

    fun importFromSafUri(
        context: Context,
        uri: Uri,
        passphrase: String,
        onSnackbar: (String) -> Unit
    ) {
        if (_isBusy.value) return
        viewModelScope.launch {
            _isBusy.value = true
            try {
                val content = withContext(Dispatchers.IO) {
                    try {
                        context.contentResolver.openInputStream(uri)?.use { stream ->
                            stream.bufferedReader(StandardCharsets.UTF_8).readText()
                        }
                    } catch (_: Exception) {
                        null
                    }
                }
                if (content.isNullOrBlank()) {
                    _statusIsError.value = true
                    _statusMessage.value = "⚠ 无法读取备份文件或文件内容为空"
                } else {
                    performImport(content.trim(), passphrase, onSnackbar)
                }
            } finally {
                _isBusy.value = false
            }
        }
    }

    private suspend fun performImport(
        rawCiphertext: String,
        passphrase: String,
        onSnackbar: (String) -> Unit
    ) {
        val res = withContext(Dispatchers.Default) {
            BackupManager.importEncryptedBackup(rawCiphertext, passphrase)
        }
        when (res) {
            is BackupImportResult.Ok -> {
                val payload = res.payload
                payload.workspaces.forEach { tokenRepository.addWorkspaceIfAbsent(it) }
                payload.tags.forEach { tokenRepository.addTagIfAbsent(it) }
                val validWs = payload.workspaces.map { it.id }.toSet()
                val localWs = tokenRepository.workspaces.value.map { it.id }.toSet()
                val fallbackWsId = tokenRepository.workspaces.value.firstOrNull()?.id
                    ?: Workspace.DEFAULT_PERSONAL.id
                val fixedTokens = payload.tokens.map { token ->
                    if (token.workspaceId in validWs || token.workspaceId in localWs) token
                    else token.copy(workspaceId = fallbackWsId)
                }
                val (added, skipped) = tokenRepository.addTokensDedup(fixedTokens)
                val corruptNote = if (res.skippedCorruptTokens > 0) "，忽略损坏 ${res.skippedCorruptTokens} 条" else ""
                _statusIsError.value = false
                _statusMessage.value = "恢复完成：新增 $added 个凭据，跳过重复 $skipped 个$corruptNote；工作区 ${payload.workspaces.size}、标签 ${payload.tags.size}"
                onSnackbar("恢复完成：新增 $added，跳过 $skipped")
            }
            is BackupImportResult.Error -> {
                _statusIsError.value = true
                _statusMessage.value = "⚠ ${res.message}"
            }
        }
    }

    fun verifyPinForBatchExport(
        pin: String,
        onResult: (SecurityLockManager.VerifyResult) -> Unit
    ) {
        viewModelScope.launch {
            val res = securityManager.verifyPin(pin)
            if (res is SecurityLockManager.VerifyResult.DuressTriggered ||
                res is SecurityLockManager.VerifyResult.SelfDestructed
            ) {
                tokenRepository.wipeInMemoryState()
                preferencesRepository?.clearAllPreferences()
            }
            onResult(res)
        }
    }

    suspend fun buildMigrationExportPlan(tokens: List<AuthToken>): MigrationExportPlan {
        return withContext(Dispatchers.Default) {
            GoogleMigrationEncoder.buildExportPlan(tokens)
        }
    }

    suspend fun renderQrBitmapAsync(uri: String, sizePx: Int = 760): Bitmap? {
        return withContext(Dispatchers.Default) {
            QrBitmapRenderer.renderQrBitmap(uri, sizePx)
        }
    }

    class Factory(
        private val tokenRepository: TokenVaultRepository,
        private val securityManager: SecurityLockManager,
        private val preferencesRepository: VaultPreferencesRepository? = null
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return BackupViewModel(tokenRepository, securityManager, preferencesRepository) as T
        }
    }
}
