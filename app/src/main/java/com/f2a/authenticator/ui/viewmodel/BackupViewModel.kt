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
import com.f2a.authenticator.totp.ExternalImportParser
import com.f2a.authenticator.totp.GoogleMigrationEncoder
import com.f2a.authenticator.totp.MigrationExportPlan
import com.f2a.authenticator.ui.utils.QrBitmapRenderer
import com.f2a.authenticator.utils.ClipboardGuard
import com.f2a.authenticator.utils.SecureClipboard
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

class BackupViewModel(
    private val tokenRepository: TokenVaultRepository,
    private val securityManager: SecurityLockManager,
    private val preferencesRepository: VaultPreferencesRepository? = null,
    private val defaultDispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
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

    private val _selfDestructedEvent = MutableStateFlow(false)
    val selfDestructedEvent: StateFlow<Boolean> = _selfDestructedEvent.asStateFlow()

    fun clearStatus() {
        _statusMessage.value = ""
        _statusIsError.value = false
    }

    fun resetSessionState() {
        clearStatus()
        _selfDestructedEvent.value = false
    }

    fun getClipboardClearSeconds(): Int = securityManager.getClipboardClearSeconds()

    /**
     * 评估备份口令强度：0=过短(<8或空白)，1=弱，2=中，3=强
     */
    fun evaluatePassphraseStrength(passphrase: String): Int {
        if (passphrase.isBlank() || passphrase.length < MIN_EXPORT_PASSPHRASE_LENGTH) return 0
        var categories = 0
        if (passphrase.any { it.isLowerCase() }) categories++
        if (passphrase.any { it.isUpperCase() }) categories++
        if (passphrase.any { it.isDigit() }) categories++
        if (passphrase.any { !it.isLetterOrDigit() }) categories++
        return when {
            passphrase.length >= 12 && categories >= 3 -> 3
            passphrase.length >= 10 && categories >= 2 -> 2
            passphrase.length >= 12 -> 2
            else -> 1
        }
    }

    fun exportToClipboard(
        context: Context,
        passphrase: String,
        onSnackbar: (String) -> Unit
    ) {
        if (_isBusy.value) return
        if (passphrase.isBlank() || passphrase.length < MIN_EXPORT_PASSPHRASE_LENGTH) {
            _statusIsError.value = true
            _statusMessage.value = "⚠ 为保障种子安全，灾备口令至少需要 $MIN_EXPORT_PASSPHRASE_LENGTH 位非空白字符"
            return
        }
        val payload = BackupPayload(
            workspaces = workspaces.value,
            tags = tags.value,
            tokens = tokens.value
        )
        viewModelScope.launch {
            _isBusy.value = true
            try {
                val res = withContext(defaultDispatcher) {
                    BackupManager.exportEncryptedBackup(payload, passphrase)
                }
                when (res) {
                    is BackupExportResult.Ok -> {
                        val clearSec = securityManager.getClipboardClearSeconds().let { if (it <= 0) 30 else it.coerceAtMost(30) }
                        SecureClipboard.copySensitive(context, res.encodedBase64, clearSec)
                        preferencesRepository?.recordBackupCompleted(System.currentTimeMillis(), res.exportedCount)
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
        if (passphrase.isBlank() || passphrase.length < MIN_EXPORT_PASSPHRASE_LENGTH) {
            _statusIsError.value = true
            _statusMessage.value = "⚠ 为保障种子安全，灾备口令至少需要 $MIN_EXPORT_PASSPHRASE_LENGTH 位非空白字符"
            return
        }
        val payload = BackupPayload(
            workspaces = workspaces.value,
            tags = tags.value,
            tokens = tokens.value
        )
        viewModelScope.launch {
            _isBusy.value = true
            try {
                val res = withContext(defaultDispatcher) {
                    BackupManager.exportEncryptedBackup(payload, passphrase)
                }
                when (res) {
                    is BackupExportResult.Ok -> {
                        val writeOk = withContext(ioDispatcher) {
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
                            preferencesRepository?.recordBackupCompleted(System.currentTimeMillis(), res.exportedCount)
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
                val readResult = withContext(ioDispatcher) {
                    try {
                        context.contentResolver.openInputStream(uri)?.use { stream ->
                            val out = ByteArrayOutputStream()
                            val buf = ByteArray(8192)
                            var total = 0
                            while (true) {
                                val n = stream.read(buf)
                                if (n < 0) break
                                total += n
                                if (total > MAX_SAF_IMPORT_BYTES) {
                                    return@withContext SafReadResult.TooLarge
                                }
                                out.write(buf, 0, n)
                            }
                            SafReadResult.Ok(String(out.toByteArray(), StandardCharsets.UTF_8))
                        } ?: SafReadResult.Failed
                    } catch (_: Exception) {
                        SafReadResult.Failed
                    }
                }
                when (readResult) {
                    is SafReadResult.Ok -> {
                        if (readResult.content.isBlank()) {
                            _statusIsError.value = true
                            _statusMessage.value = "⚠ 无法读取备份文件或文件内容为空"
                        } else {
                            performImport(readResult.content.trim(), passphrase, onSnackbar)
                        }
                    }
                    SafReadResult.TooLarge -> {
                        _statusIsError.value = true
                        _statusMessage.value = "⚠ 备份文件超过 10MB 上限，已拒绝读取"
                    }
                    SafReadResult.Failed -> {
                        _statusIsError.value = true
                        _statusMessage.value = "⚠ 无法读取备份文件或文件权限受限"
                    }
                }
            } finally {
                _isBusy.value = false
            }
        }
    }

    fun importExternalText(
        rawText: String,
        targetWorkspaceId: String
    ) {
        if (_isBusy.value) return
        viewModelScope.launch {
            _isBusy.value = true
            try {
                val parsed = withContext(defaultDispatcher) {
                    ExternalImportParser.parse(
                        rawInput = rawText,
                        defaultWorkspaceId = targetWorkspaceId,
                        existingWorkspaces = tokenRepository.workspaces.value
                    )
                }
                if (parsed.tokens.isEmpty()) {
                    _statusIsError.value = true
                    _statusMessage.value = "⚠ ${parsed.warnings.firstOrNull() ?: "未识别到可导入的有效 2FA 凭据"}"
                    return@launch
                }
                val (added, dupSkipped) = tokenRepository.addTokensDedup(parsed.tokens)
                val skipTotal = dupSkipped + parsed.skippedCount
                val skipText = if (skipTotal > 0) "，跳过重复或无效 $skipTotal 条" else ""
                _statusIsError.value = false
                _statusMessage.value = "已按「${parsed.formatName}」导入：新增 $added 个凭据$skipText"
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
        val res = withContext(defaultDispatcher) {
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
        context: Context? = null,
        onResult: (SecurityLockManager.VerifyResult) -> Unit
    ) {
        viewModelScope.launch {
            val res = securityManager.verifyPin(pin)
            if (res is SecurityLockManager.VerifyResult.DuressTriggered ||
                res is SecurityLockManager.VerifyResult.SelfDestructed
            ) {
                tokenRepository.wipeInMemoryState()
                preferencesRepository?.clearAllPreferences()
                context?.let { ClipboardGuard.clearNow(it) }
                if (res is SecurityLockManager.VerifyResult.SelfDestructed) {
                    _selfDestructedEvent.value = true
                }
            }
            onResult(res)
        }
    }

    fun verifyPinForBatchExport(
        pin: String,
        onResult: (SecurityLockManager.VerifyResult) -> Unit
    ) {
        verifyPinForBatchExport(pin = pin, context = null, onResult = onResult)
    }

    suspend fun buildMigrationExportPlan(tokens: List<AuthToken>): MigrationExportPlan {
        return withContext(defaultDispatcher) {
            GoogleMigrationEncoder.buildExportPlan(tokens)
        }
    }

    suspend fun renderQrBitmapAsync(uri: String, sizePx: Int = 760): Bitmap? {
        return withContext(defaultDispatcher) {
            QrBitmapRenderer.renderQrBitmap(uri, sizePx)
        }
    }

    private sealed interface SafReadResult {
        data class Ok(val content: String) : SafReadResult
        data object TooLarge : SafReadResult
        data object Failed : SafReadResult
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

    companion object {
        private const val MIN_EXPORT_PASSPHRASE_LENGTH = 8
        private const val MAX_SAF_IMPORT_BYTES = 10 * 1024 * 1024
    }
}
