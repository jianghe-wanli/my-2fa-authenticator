package com.f2a.authenticator.ui.screens.dialogs

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.f2a.authenticator.ui.components.EmptyStateCompact
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type
import com.f2a.authenticator.ui.viewmodel.BackupViewModel
import kotlinx.coroutines.launch

@Composable
fun BackupDialog(
    viewModel: BackupViewModel,
    onSuppressNextBackgroundLock: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val semantic = LocalSemanticColors.current

    val workspaces by viewModel.workspaces.collectAsState()
    val tokens by viewModel.tokens.collectAsState()
    val isBusy by viewModel.isBusy.collectAsState()
    val statusMessage by viewModel.statusMessage.collectAsState()
    val statusIsError by viewModel.statusIsError.collectAsState()

    var isExportMode by remember { mutableStateOf(true) }
    // 【安全红线】灾备口令与密文导入文本禁止使用 rememberSaveable
    var passphrase by remember { mutableStateOf("") }
    var importData by remember { mutableStateOf("") }
    var showPassphrase by remember { mutableStateOf(false) }

    val snackbarHostState = remember { SnackbarHostState() }
    val uiScope = rememberCoroutineScope()
    val showSnack: (String) -> Unit = { msg ->
        uiScope.launch {
            snackbarHostState.currentSnackbarData?.dismiss()
            snackbarHostState.showSnackbar(msg)
        }
    }

    val createFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri != null && passphrase.isNotBlank()) {
            viewModel.exportToSafUri(context, uri, passphrase, showSnack)
        }
    }

    val openFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null && passphrase.isNotBlank()) {
            viewModel.importFromSafUri(context, uri, passphrase, showSnack)
        }
    }

    val passphraseStrength = remember(passphrase) {
        viewModel.evaluatePassphraseStrength(passphrase)
    }
    val strengthMeta = when {
        passphrase.isEmpty() -> null
        passphraseStrength == 0 -> Triple(1, "口令过短（导出至少需要 8 位非空白字符）", semantic.errorText)
        passphraseStrength == 1 -> Triple(2, "口令强度：较弱（建议混用大小写与数字/符号）", semantic.timerWarning)
        passphraseStrength == 2 -> Triple(3, "口令强度：中等", semantic.timerNormal)
        else -> Triple(4, "口令强度：强", semantic.success)
    }
    val canExportWithPassphrase = passphrase.isNotBlank() && passphraseStrength >= 1

    val screenHeight = LocalConfiguration.current.screenHeightDp.dp

    Dialog(
        onDismissRequest = { if (!isBusy) onDismiss() },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)
    ) {
        Card(
            shape = RoundedCornerShape(Radius.XL),
            colors = CardDefaults.cardColors(containerColor = semantic.surfaceElevated),
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = Space.M)
                .border(1.dp, semantic.borderSubtle, RoundedCornerShape(Radius.XL))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = screenHeight * 0.88f)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = Space.XL, end = Space.S, top = Space.S),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("端到端加密灾备", style = Type.TitleSection, modifier = Modifier.weight(1f))
                    IconButton(onClick = onDismiss, enabled = !isBusy, modifier = Modifier.size(Touch.MinTarget)) {
                        Icon(Icons.Default.Close, contentDescription = "关闭", modifier = Modifier.size(IconSize.M))
                    }
                }

                Column(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .verticalScroll(rememberScrollState())
                        .imePadding()
                        .padding(horizontal = Space.XL)
                ) {
                    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                        SegmentedButton(
                            selected = isExportMode,
                            onClick = { isExportMode = true; viewModel.clearStatus() },
                            shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                            modifier = Modifier.heightIn(min = Touch.SegmentedHeight)
                        ) { Text("导出备份") }
                        SegmentedButton(
                            selected = !isExportMode,
                            onClick = { isExportMode = false; viewModel.clearStatus() },
                            shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                            modifier = Modifier.heightIn(min = Touch.SegmentedHeight)
                        ) { Text("恢复导入") }
                    }

                    Spacer(modifier = Modifier.height(Space.L))

                    OutlinedTextField(
                        value = passphrase,
                        onValueChange = { passphrase = it; viewModel.clearStatus() },
                        label = { Text("灾备加密口令 (自设独立密码)") },
                        singleLine = true,
                        visualTransformation = if (showPassphrase) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { showPassphrase = !showPassphrase }, modifier = Modifier.size(Touch.MinTarget)) {
                                Icon(
                                    imageVector = if (showPassphrase) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                    contentDescription = if (showPassphrase) "隐藏口令" else "显示口令",
                                    modifier = Modifier.size(IconSize.M)
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(Radius.M)
                    )

                    if (isExportMode && strengthMeta != null) {
                        val (activeSegments, label, barColor) = strengthMeta
                        Spacer(modifier = Modifier.height(Space.S))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(Space.XS)
                        ) {
                            repeat(4) { idx ->
                                Box(
                                    modifier = Modifier
                                        .weight(1f)
                                        .height(4.dp)
                                        .clip(RoundedCornerShape(Radius.Full))
                                        .background(
                                            if (idx < activeSegments) barColor
                                            else MaterialTheme.colorScheme.surfaceVariant
                                        )
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(Space.XS))
                        Text(text = label, style = Type.Caption, color = barColor)
                    }

                    if (isExportMode) {
                        Spacer(modifier = Modifier.height(Space.M))
                        if (tokens.isEmpty()) {
                            EmptyStateCompact(
                                icon = Icons.Default.Save,
                                title = "暂无可备份的凭据",
                                description = "请先添加 2FA 凭据后再进行加密灾备"
                            )
                        } else {
                            Text(
                                text = "将使用 PBKDF2-HMAC-SHA256 (210K) + AES-256-GCM 加密 ${workspaces.size} 个工作区和 ${tokens.size} 个活跃凭据。",
                                style = Type.BodyS,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.height(Space.M))
                            OutlinedButton(
                                enabled = !isBusy && canExportWithPassphrase,
                                onClick = {
                                    onSuppressNextBackgroundLock()
                                    try {
                                        createFileLauncher.launch("my2fa-backup-${System.currentTimeMillis()}.jdf2")
                                    } catch (_: Exception) {
                                        showSnack("未找到系统文件管理器，请改用「生成并复制」")
                                    }
                                },
                                shape = RoundedCornerShape(Radius.M),
                                modifier = Modifier.fillMaxWidth().heightIn(min = Touch.MinTarget)
                            ) {
                                Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(IconSize.S))
                                Spacer(modifier = Modifier.width(Space.XS))
                                Text("导出为 .jdf2 备份文件")
                            }
                        }
                    } else {
                        Spacer(modifier = Modifier.height(Space.M))
                        OutlinedTextField(
                            value = importData,
                            onValueChange = { importData = it; viewModel.clearStatus() },
                            label = { Text("粘贴加密备份密文") },
                            modifier = Modifier.fillMaxWidth().height(120.dp),
                            shape = RoundedCornerShape(Radius.M)
                        )
                        Spacer(modifier = Modifier.height(Space.S))
                        OutlinedButton(
                            enabled = !isBusy && passphrase.isNotBlank(),
                            onClick = {
                                onSuppressNextBackgroundLock()
                                try {
                                    openFileLauncher.launch(arrayOf("*/*"))
                                } catch (_: Exception) {
                                    showSnack("未找到系统文件选择器，请改用密文粘贴导入")
                                }
                            },
                            shape = RoundedCornerShape(Radius.M),
                            modifier = Modifier.fillMaxWidth().heightIn(min = Touch.MinTarget)
                        ) {
                            Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(IconSize.S))
                            Spacer(modifier = Modifier.width(Space.XS))
                            Text("从 .jdf2 备份文件导入")
                        }
                    }

                    if (statusMessage.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(Space.S))
                        Text(
                            text = statusMessage,
                            color = if (statusIsError) semantic.errorText else semantic.success,
                            style = Type.BodyS,
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    Spacer(modifier = Modifier.height(Space.S))
                }

                SnackbarHost(hostState = snackbarHostState)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .padding(horizontal = Space.XL, vertical = Space.M),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (isBusy) {
                        CircularProgressIndicator(modifier = Modifier.size(IconSize.L), strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(Space.M))
                    }
                    TextButton(
                        enabled = !isBusy,
                        onClick = onDismiss,
                        modifier = Modifier.heightIn(min = Touch.MinTarget)
                    ) { Text("关闭") }
                    Spacer(modifier = Modifier.width(Space.S))
                    Button(
                        enabled = !isBusy && if (isExportMode) (canExportWithPassphrase && tokens.isNotEmpty()) else passphrase.isNotBlank(),
                        onClick = {
                            if (isExportMode) {
                                viewModel.exportToClipboard(context, passphrase, showSnack)
                            } else if (importData.isBlank()) {
                                showSnack("请先粘贴加密备份密文或选择文件导入")
                            } else {
                                viewModel.importFromString(importData, passphrase, showSnack)
                            }
                        },
                        shape = RoundedCornerShape(Radius.M),
                        modifier = Modifier.heightIn(min = Touch.MinTarget)
                    ) {
                        Text(if (isExportMode) "生成并复制" else "解密并导入")
                    }
                }
            }
        }
    }
}
