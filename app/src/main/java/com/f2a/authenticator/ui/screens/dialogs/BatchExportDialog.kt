package com.f2a.authenticator.ui.screens.dialogs

import android.graphics.Bitmap
import androidx.compose.foundation.Image
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
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.f2a.authenticator.security.SecurityLockManager
import com.f2a.authenticator.totp.GoogleMigrationEncoder
import com.f2a.authenticator.totp.MigrationExportPlan
import com.f2a.authenticator.ui.components.EmptyStateCompact
import com.f2a.authenticator.ui.screens.settings.PinField
import com.f2a.authenticator.ui.screens.settings.formatVerifyError
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type
import com.f2a.authenticator.ui.viewmodel.BackupViewModel
import com.f2a.authenticator.utils.SecureClipboard
import kotlinx.coroutines.launch

@Composable
fun BatchExportDialog(
    viewModel: BackupViewModel,
    onSelfDestructed: () -> Unit = {},
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val semantic = LocalSemanticColors.current
    val tokens by viewModel.tokens.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val uiScope = rememberCoroutineScope()

    // 【安全红线】二次鉴权态与 PIN 输入严禁使用 rememberSaveable
    var isAuthorized by remember { mutableStateOf(false) }
    var inputPin by remember { mutableStateOf("") }
    var authError by remember { mutableStateOf("") }
    var isVerifying by remember { mutableStateOf(false) }

    var exportPlan by remember { mutableStateOf<MigrationExportPlan?>(null) }
    var currentBatchIndex by remember { mutableIntStateOf(0) }
    var currentQrBitmap by remember { mutableStateOf<Bitmap?>(null) }
    var isRenderingQr by remember { mutableStateOf(false) }

    LaunchedEffect(isAuthorized, tokens) {
        if (isAuthorized) {
            exportPlan = viewModel.buildMigrationExportPlan(tokens)
            currentBatchIndex = 0
        }
    }

    val currentUri = exportPlan?.uris?.getOrNull(currentBatchIndex)
    LaunchedEffect(currentUri) {
        if (currentUri != null) {
            isRenderingQr = true
            currentQrBitmap = viewModel.renderQrBitmapAsync(currentUri, 760)
            isRenderingQr = false
        } else {
            currentQrBitmap = null
        }
    }

    val screenHeight = LocalConfiguration.current.screenHeightDp.dp

    Dialog(onDismissRequest = onDismiss) {
        Card(
            shape = RoundedCornerShape(Radius.XL),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = Space.M)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = screenHeight * 0.9f)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = Space.XXL, end = Space.S, top = Space.S),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = if (!isAuthorized) "导出安全验证" else "转移与批量导出",
                        style = Type.TitleSection,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = onDismiss, modifier = Modifier.size(Touch.MinTarget)) {
                        Icon(Icons.Default.Close, contentDescription = "关闭", modifier = Modifier.size(IconSize.M))
                    }
                }

                Column(
                    modifier = Modifier
                        .weight(1f, fill = false)
                        .verticalScroll(rememberScrollState())
                        .imePadding()
                        .padding(horizontal = Space.XXL),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    if (!isAuthorized) {
                        Icon(
                            imageVector = Icons.Default.Lock,
                            contentDescription = "安全锁定",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(44.dp)
                        )
                        Spacer(modifier = Modifier.height(Space.M))
                        Text(
                            text = "批量导出将生成账号迁移凭据，请输入 6 位主安全密码以授权。",
                            style = Type.BodyS,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(Space.L))
                        PinField(
                            value = inputPin,
                            onValueChange = { inputPin = it; authError = "" },
                            label = "6 位独立主密码"
                        )
                        if (authError.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(Space.HS))
                            Text("⚠ $authError", color = semantic.errorText, style = Type.BodyS, fontWeight = FontWeight.Bold)
                        }
                        Spacer(modifier = Modifier.height(Space.S))
                    } else {
                        val plan = exportPlan
                        val uris = plan?.uris ?: emptyList()
                        val skippedCount = plan?.skippedIncompatibleTokens?.size ?: 0
                        val degradedCount = plan?.degradedPeriodTokens?.size ?: 0

                        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(Radius.XS))
                                    .background(MaterialTheme.colorScheme.primaryContainer)
                                    .padding(horizontal = Space.S, vertical = Space.XXS + 1.dp)
                            ) {
                                Text(
                                    text = "可导出 ${plan?.exportedCount ?: 0} 个凭据",
                                    style = Type.Label,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(Space.S))
                        Text(
                            text = "使用其它手机打开 Google Authenticator 或极盾 2FA，扫描或导入此协议即可一次性迁走账号。",
                            style = Type.BodyS,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        if (skippedCount > 0) {
                            Spacer(modifier = Modifier.height(Space.S))
                            Text(
                                text = "注意：有 $skippedCount 个令牌（Steam / 密钥损坏 / 空密钥）无法无损导出，已自动跳过。",
                                style = Type.Caption,
                                color = semantic.errorText,
                                fontWeight = FontWeight.Bold
                            )
                        }

                        if (degradedCount > 0) {
                            Spacer(modifier = Modifier.height(Space.XS))
                            Text(
                                text = "提示：有 $degradedCount 个非 30s 周期令牌，Google 迁移协议标准默认按 30s 周期解释。",
                                style = Type.Caption,
                                color = semantic.timerWarning,
                                fontWeight = FontWeight.Bold
                            )
                        }

                        Spacer(modifier = Modifier.height(Space.L))

                        if (uris.isNotEmpty()) {
                            Card(
                                shape = RoundedCornerShape(Radius.L),
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .border(1.dp, semantic.borderSubtle, RoundedCornerShape(Radius.L))
                            ) {
                                Column(
                                    modifier = Modifier.fillMaxWidth().padding(Space.L),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(240.dp)
                                            .clip(RoundedCornerShape(Radius.S))
                                            .background(Color.White)
                                            .padding(Space.MS),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        val bmp = currentQrBitmap
                                        when {
                                            isRenderingQr -> CircularProgressIndicator(modifier = Modifier.size(IconSize.XL))
                                            bmp != null -> Image(
                                                bitmap = bmp.asImageBitmap(),
                                                contentDescription = "迁移二维码",
                                                modifier = Modifier.size(220.dp)
                                            )
                                            else -> Icon(Icons.Default.QrCode2, contentDescription = "迁移二维码", modifier = Modifier.size(IconSize.Hero))
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(Space.S))
                                    Text(
                                        text = "Google 迁移协议包 (第 ${currentBatchIndex + 1} / ${uris.size} 包)",
                                        fontWeight = FontWeight.Bold,
                                        style = Type.BodyS,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(modifier = Modifier.height(Space.HS))
                                    Text(
                                        text = "单包上限 ${GoogleMigrationEncoder.MAX_TOKENS_PER_QR} 个，自动防拥挤优化",
                                        style = Type.Caption,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Spacer(modifier = Modifier.height(Space.M))

                                    FilledTonalButton(
                                        onClick = {
                                            val uri = currentUri ?: return@FilledTonalButton
                                            val clearSec = viewModel.getClipboardClearSeconds().let { if (it <= 0) 30 else it.coerceAtMost(30) }
                                            SecureClipboard.copySensitive(context, uri, clearSec)
                                            uiScope.launch {
                                                snackbarHostState.currentSnackbarData?.dismiss()
                                                snackbarHostState.showSnackbar("已复制第 ${currentBatchIndex + 1} 包链接（${clearSec}s 后自动清除）")
                                            }
                                        },
                                        shape = RoundedCornerShape(Radius.M),
                                        modifier = Modifier.heightIn(min = Touch.MinTarget)
                                    ) {
                                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(IconSize.S))
                                        Spacer(modifier = Modifier.width(Space.HS))
                                        Text("复制第 ${currentBatchIndex + 1} 包协议链接", style = Type.BodyS, fontWeight = FontWeight.Bold)
                                    }
                                }
                            }

                            if (uris.size > 1) {
                                Spacer(modifier = Modifier.height(Space.M))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    IconButton(
                                        onClick = { currentBatchIndex = (currentBatchIndex - 1).coerceAtLeast(0) },
                                        enabled = currentBatchIndex > 0,
                                        modifier = Modifier.size(Touch.MinTarget)
                                    ) { Icon(Icons.Default.ChevronLeft, contentDescription = "上一包") }

                                    Text(text = "第 ${currentBatchIndex + 1} / ${uris.size} 包", style = Type.BodyS, fontWeight = FontWeight.Bold)

                                    IconButton(
                                        onClick = { currentBatchIndex = (currentBatchIndex + 1).coerceAtMost(uris.size - 1) },
                                        enabled = currentBatchIndex < uris.size - 1,
                                        modifier = Modifier.size(Touch.MinTarget)
                                    ) { Icon(Icons.Default.ChevronRight, contentDescription = "下一包") }
                                }
                            }
                        } else if (plan != null) {
                            EmptyStateCompact(
                                icon = Icons.Default.QrCode2,
                                title = "暂无可导出凭据",
                                description = "当前没有可导出的 2FA 凭据，请先添加后再批量导出"
                            )
                        }
                        Spacer(modifier = Modifier.height(Space.S))
                    }
                }

                // Snackbar 置于可滚区与 Footer 之间，永不遮挡底部按钮
                SnackbarHost(hostState = snackbarHostState)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .padding(horizontal = Space.XXL, vertical = Space.M),
                    horizontalArrangement = Arrangement.End
                ) {
                    if (!isAuthorized) {
                        TextButton(onClick = onDismiss, modifier = Modifier.heightIn(min = Touch.MinTarget)) { Text("取消") }
                        Spacer(modifier = Modifier.width(Space.S))
                        Button(
                            enabled = !isVerifying && inputPin.length == 6,
                            onClick = {
                                isVerifying = true
                                viewModel.verifyPinForBatchExport(inputPin) { verify ->
                                    isVerifying = false
                                    when (verify) {
                                        is SecurityLockManager.VerifyResult.Success -> {
                                            isAuthorized = true
                                        }
                                        is SecurityLockManager.VerifyResult.DuressTriggered -> {
                                            onDismiss()
                                        }
                                        is SecurityLockManager.VerifyResult.SelfDestructed -> {
                                            onDismiss()
                                            onSelfDestructed()
                                        }
                                        else -> {
                                            authError = formatVerifyError(verify)
                                        }
                                    }
                                }
                            },
                            shape = RoundedCornerShape(Radius.M),
                            modifier = Modifier.heightIn(min = Touch.MinTarget)
                        ) { Text("验证并导出") }
                    } else {
                        Button(
                            onClick = onDismiss,
                            shape = RoundedCornerShape(Radius.M),
                            modifier = Modifier.heightIn(min = Touch.MinTarget)
                        ) { Text("完成") }
                    }
                }
            }
        }
    }
}
