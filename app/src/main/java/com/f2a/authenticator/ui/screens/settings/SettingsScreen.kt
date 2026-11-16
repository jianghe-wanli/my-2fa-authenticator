package com.f2a.authenticator.ui.screens.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.f2a.authenticator.data.model.AutoLockTimeout
import com.f2a.authenticator.data.model.CollapsePolicy
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.ThemeMode
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.BiometricStatus
import com.f2a.authenticator.security.PinConfigResult
import com.f2a.authenticator.security.SecurityLockManager
import com.f2a.authenticator.ui.components.parseHexColor
import com.f2a.authenticator.ui.screens.home.CreateTagDialog
import com.f2a.authenticator.ui.state.SettingsUiState
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    uiState: SettingsUiState,
    onBack: () -> Unit,
    onLockNow: () -> Unit,
    onOpenBackup: () -> Unit,
    onOpenBatchExport: () -> Unit,
    onSetMaxAttempts: (Int) -> Unit,
    onSetFlagSecure: (Boolean) -> Unit,
    onSetClipboardClearSeconds: (Int) -> Unit,
    onSetBiometricEnabled: (Boolean) -> Unit,
    onSetThemeMode: (ThemeMode) -> Unit,
    onSetCollapsePolicy: (CollapsePolicy) -> Unit,
    onSetAutoLockTimeout: (AutoLockTimeout) -> Unit,
    onChangeMasterPin: (String, String, (PinConfigResult) -> Unit) -> Unit,
    onSetDuressPin: (String, String, (PinConfigResult) -> Unit) -> Unit,
    onClearDuressPin: (String, (PinConfigResult) -> Unit) -> Unit,
    onVerifyAndClearAll: (String, (SecurityLockManager.VerifyResult) -> Unit) -> Unit,
    onSelfDestructed: () -> Unit = {},
    onExecuteSelfDestruct: () -> Unit,
    onAddWorkspace: (String) -> Unit,
    onRenameWorkspace: (String, String) -> Unit,
    onDeleteWorkspace: (String) -> Unit,
    onAddTag: (String, String) -> Unit,
    onDeleteTag: (String) -> Unit,
    onRestoreTrashToken: (String) -> Unit,
    onPermanentDeleteTrashToken: (String) -> Unit,
    onEmptyTrash: () -> Unit
) {
    val semantic = LocalSemanticColors.current
    val snackbarHostState = remember { SnackbarHostState() }
    val uiScope = rememberCoroutineScope()
    val showSnack: (String) -> Unit = { msg ->
        uiScope.launch {
            snackbarHostState.currentSnackbarData?.dismiss()
            snackbarHostState.showSnackbar(msg)
        }
    }

    BackHandler(onBack = onBack)

    var expandSecurity by rememberSaveable { mutableStateOf(true) }
    var expandAppearance by rememberSaveable { mutableStateOf(false) }
    var expandWorkspaces by rememberSaveable { mutableStateOf(false) }
    var expandBackup by rememberSaveable { mutableStateOf(false) }
    var expandDanger by rememberSaveable { mutableStateOf(false) }

    var showChangePinDialog by remember { mutableStateOf(false) }
    var showDuressDialog by remember { mutableStateOf(false) }
    var showAddWorkspaceDialog by remember { mutableStateOf(false) }
    var workspaceToRename by remember { mutableStateOf<Workspace?>(null) }
    var workspaceToDelete by remember { mutableStateOf<Workspace?>(null) }
    var showAddTagDialog by remember { mutableStateOf(false) }
    var tagToDelete by remember { mutableStateOf<Tag?>(null) }
    var showTrashDialog by remember { mutableStateOf(false) }
    var showConfirmClearDialog by remember { mutableStateOf(false) }
    var showDestructInputDialog by remember { mutableStateOf(false) }
    var showDestructCountdownDialog by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("设置与安全中心", style = Type.TitlePage) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.size(Touch.MinTarget)) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回", modifier = Modifier.size(IconSize.L))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background)
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = PaddingValues(start = Space.L, end = Space.L, top = Space.MS, bottom = Space.X4L)
        ) {
            item(key = "sec_card") {
                SettingsAccordionCard(
                    title = "安全与隐私",
                    subtitle = "主密码 · 胁迫码 · 生物识别 · 自动锁定",
                    icon = Icons.Default.Shield,
                    isExpanded = expandSecurity,
                    onToggle = { expandSecurity = !expandSecurity }
                ) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        SettingRow(title = "修改主密码", description = "更换 6 位独立保险库解锁密码") {
                            TextButton(onClick = { showChangePinDialog = true }) { Text("修改") }
                        }
                        SettingDivider()

                        SettingRow(
                            title = "胁迫销毁密码",
                            description = if (uiState.hasDuressPin) "已配置（输入即静默抹除进入空库）" else "未设置（紧急情况下静默清空数据）"
                        ) {
                            TextButton(onClick = { showDuressDialog = true }) {
                                Text(if (uiState.hasDuressPin) "管理" else "设置")
                            }
                        }
                        SettingDivider()

                        val bioAvailable = uiState.biometricStatus == BiometricStatus.AVAILABLE
                        SettingRow(
                            title = "生物识别解锁",
                            description = when (uiState.biometricStatus) {
                                BiometricStatus.AVAILABLE -> "允许使用指纹或面容快速解锁"
                                BiometricStatus.NONE_ENROLLED -> "系统尚未录入指纹或面容"
                                else -> "当前设备不支持强生物识别"
                            }
                        ) {
                            Switch(
                                checked = uiState.biometricEnabled && bioAvailable,
                                enabled = bioAvailable,
                                onCheckedChange = {
                                    onSetBiometricEnabled(it)
                                    showSnack(if (it) "已开启生物识别解锁" else "已关闭生物识别解锁")
                                }
                            )
                        }
                        SettingDivider()

                        Column(modifier = Modifier.padding(vertical = Space.M)) {
                            Text("后台自动锁定超时", style = Type.BodyM, fontWeight = FontWeight.Bold)
                            Spacer(modifier = Modifier.height(Space.S))
                            val timeouts = listOf(
                                AutoLockTimeout.IMMEDIATE to "立即",
                                AutoLockTimeout.SECONDS_30 to "30秒",
                                AutoLockTimeout.SECONDS_60 to "1分",
                                AutoLockTimeout.SECONDS_300 to "5分",
                                AutoLockTimeout.NEVER to "关闭"
                            )
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                timeouts.forEachIndexed { idx, (timeout, label) ->
                                    SegmentedButton(
                                        selected = uiState.autoLockTimeout == timeout,
                                        onClick = { onSetAutoLockTimeout(timeout) },
                                        shape = SegmentedButtonDefaults.itemShape(index = idx, count = timeouts.size),
                                        modifier = Modifier.heightIn(min = Touch.SegmentedHeight)
                                    ) { Text(label, style = Type.Caption) }
                                }
                            }
                        }
                        SettingDivider()

                        Column(modifier = Modifier.padding(vertical = Space.M)) {
                            Text("自毁触发阈值", style = Type.BodyM, fontWeight = FontWeight.Bold)
                            Text(
                                text = "连续错误 ${uiState.maxAttempts} 次即物理自毁",
                                style = Type.BodyS,
                                color = MaterialTheme.colorScheme.error,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(modifier = Modifier.height(Space.S))
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                listOf(3, 5, 10).forEachIndexed { idx, count ->
                                    SegmentedButton(
                                        selected = uiState.maxAttempts == count,
                                        onClick = {
                                            onSetMaxAttempts(count)
                                            showSnack("自毁阈值已设为 $count 次")
                                        },
                                        shape = SegmentedButtonDefaults.itemShape(index = idx, count = 3),
                                        modifier = Modifier.heightIn(min = Touch.SegmentedHeight)
                                    ) { Text("${count} 次", style = Type.BodyS) }
                                }
                            }
                        }
                        SettingDivider()

                        SettingRow(
                            title = "防屏幕截图与录屏 (FLAG_SECURE)",
                            description = "禁止系统后台截屏、录屏与多任务卡片偷窥"
                        ) {
                            Switch(
                                checked = uiState.flagSecureEnabled,
                                onCheckedChange = {
                                    onSetFlagSecure(it)
                                    showSnack(if (it) "已开启防截屏保护" else "已临时允许截屏")
                                }
                            )
                        }
                        SettingDivider()

                        Column(modifier = Modifier.padding(vertical = Space.M)) {
                            Text("剪贴板自动清除时限", style = Type.BodyM, fontWeight = FontWeight.Bold)
                            Spacer(modifier = Modifier.height(Space.S))
                            val options = listOf(30 to "30秒", 45 to "45秒", 60 to "60秒", 0 to "关闭")
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                options.forEachIndexed { idx, (sec, label) ->
                                    SegmentedButton(
                                        selected = uiState.clipboardClearSeconds == sec,
                                        onClick = { onSetClipboardClearSeconds(sec) },
                                        shape = SegmentedButtonDefaults.itemShape(index = idx, count = 4),
                                        modifier = Modifier.heightIn(min = Touch.SegmentedHeight)
                                    ) { Text(label, style = Type.BodyS) }
                                }
                            }
                        }

                        OutlinedButton(
                            onClick = onLockNow,
                            shape = RoundedCornerShape(Radius.M),
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = Touch.MinTarget)
                        ) {
                            Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(IconSize.S))
                            Spacer(modifier = Modifier.width(Space.S))
                            Text("立即锁定保险库", style = Type.BodyM, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            item(key = "sp_1") { Spacer(modifier = Modifier.height(Space.ML)) }

            item(key = "appearance_card") {
                SettingsAccordionCard(
                    title = "界面与列表偏好",
                    subtitle = "深浅色主题 · 分类默认折叠策略",
                    icon = Icons.Default.Palette,
                    isExpanded = expandAppearance,
                    onToggle = { expandAppearance = !expandAppearance }
                ) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Text("外观主题", style = Type.BodyM, fontWeight = FontWeight.Bold)
                        Spacer(modifier = Modifier.height(Space.S))
                        val themes = listOf(
                            ThemeMode.SYSTEM to "跟随系统",
                            ThemeMode.DARK to "深色",
                            ThemeMode.LIGHT to "浅色"
                        )
                        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                            themes.forEachIndexed { idx, (mode, label) ->
                                SegmentedButton(
                                    selected = uiState.themeMode == mode,
                                    onClick = { onSetThemeMode(mode) },
                                    shape = SegmentedButtonDefaults.itemShape(index = idx, count = 3),
                                    modifier = Modifier.heightIn(min = Touch.SegmentedHeight)
                                ) { Text(label, style = Type.BodyS) }
                            }
                        }

                        Spacer(modifier = Modifier.height(Space.M))
                        SettingDivider()
                        Spacer(modifier = Modifier.height(Space.M))

                        Text("主页平台分组默认折叠策略", style = Type.BodyM, fontWeight = FontWeight.Bold)
                        Spacer(modifier = Modifier.height(Space.S))
                        val policies = listOf(
                            CollapsePolicy.COLLAPSE_ALL to "默认全折叠",
                            CollapsePolicy.EXPAND_PINNED to "仅展开置顶",
                            CollapsePolicy.REMEMBER_LAST to "记住上次"
                        )
                        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                            policies.forEachIndexed { idx, (policy, label) ->
                                SegmentedButton(
                                    selected = uiState.collapsePolicy == policy,
                                    onClick = { onSetCollapsePolicy(policy) },
                                    shape = SegmentedButtonDefaults.itemShape(index = idx, count = 3),
                                    modifier = Modifier.heightIn(min = Touch.SegmentedHeight)
                                ) { Text(label, style = Type.Caption) }
                            }
                        }
                    }
                }
            }

            item(key = "sp_2") { Spacer(modifier = Modifier.height(Space.ML)) }

            item(key = "ws_card") {
                SettingsAccordionCard(
                    title = "工作区与标签",
                    subtitle = "${uiState.workspaces.size} 个工作区，${uiState.tags.size} 个标签",
                    icon = Icons.Default.Folder,
                    isExpanded = expandWorkspaces,
                    onToggle = { expandWorkspaces = !expandWorkspaces }
                ) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("工作区列表", style = Type.BodyS, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                            TextButton(onClick = { showAddWorkspaceDialog = true }) {
                                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(IconSize.XS))
                                Spacer(modifier = Modifier.width(Space.XS))
                                Text("新建工作区", style = Type.BodyS)
                            }
                        }
                        uiState.workspaces.forEach { ws ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = Space.XXS)
                                    .clip(RoundedCornerShape(Radius.S))
                                    .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                                    .padding(horizontal = Space.M, vertical = Space.XS),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(modifier = Modifier.size(Space.S).clip(CircleShape).background(MaterialTheme.colorScheme.primary))
                                Spacer(modifier = Modifier.width(Space.MS))
                                Text(text = ws.name, modifier = Modifier.weight(1f), style = Type.BodyM)
                                IconButton(onClick = { workspaceToRename = ws }, modifier = Modifier.size(Touch.MinTarget)) {
                                    Icon(Icons.Default.Edit, contentDescription = "重命名工作区", modifier = Modifier.size(IconSize.S))
                                }
                                if (uiState.workspaces.size > 1) {
                                    IconButton(onClick = { workspaceToDelete = ws }, modifier = Modifier.size(Touch.MinTarget)) {
                                        Icon(Icons.Default.Delete, contentDescription = "删除工作区", tint = semantic.errorText, modifier = Modifier.size(IconSize.S))
                                    }
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(Space.M))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("动态标签管理", style = Type.BodyS, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                            TextButton(onClick = { showAddTagDialog = true }) {
                                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(IconSize.XS))
                                Spacer(modifier = Modifier.width(Space.XS))
                                Text("新建标签", style = Type.BodyS)
                            }
                        }
                        Column(verticalArrangement = Arrangement.spacedBy(Space.XS)) {
                            uiState.tags.forEach { tag ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(Radius.S))
                                        .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                                        .padding(horizontal = Space.M, vertical = Space.XS),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(modifier = Modifier.size(Space.S).clip(CircleShape).background(parseHexColor(tag.colorHex)))
                                    Spacer(modifier = Modifier.width(Space.MS))
                                    Text(text = tag.name, modifier = Modifier.weight(1f), style = Type.BodyM)
                                    IconButton(onClick = { tagToDelete = tag }, modifier = Modifier.size(Touch.MinTarget)) {
                                        Icon(Icons.Default.Close, contentDescription = "删除标签", tint = semantic.errorText, modifier = Modifier.size(IconSize.S))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item(key = "sp_3") { Spacer(modifier = Modifier.height(Space.ML)) }

            item(key = "backup_card") {
                SettingsAccordionCard(
                    title = "数据备份、迁移与回收站",
                    subtitle = "Google 迁移 · 加密灾备 · 回收站 (${uiState.trashedItems.size})",
                    icon = Icons.Default.Save,
                    isExpanded = expandBackup,
                    onToggle = { expandBackup = !expandBackup }
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(Space.M)) {
                        Button(
                            onClick = onOpenBatchExport,
                            modifier = Modifier.fillMaxWidth().heightIn(min = Touch.MinTarget),
                            shape = RoundedCornerShape(Radius.M)
                        ) {
                            Icon(Icons.Default.QrCode, contentDescription = null, modifier = Modifier.size(IconSize.S))
                            Spacer(modifier = Modifier.width(Space.HS))
                            Text("一键批量导出 (Google 迁移协议)", style = Type.BodyL)
                        }
                        OutlinedButton(
                            onClick = onOpenBackup,
                            modifier = Modifier.fillMaxWidth().heightIn(min = Touch.MinTarget),
                            shape = RoundedCornerShape(Radius.M)
                        ) {
                            Text("端到端全量加密灾备 (.jdf2 文件 / 密文)", style = Type.BodyL)
                        }
                        OutlinedButton(
                            onClick = { showTrashDialog = true },
                            modifier = Modifier.fillMaxWidth().heightIn(min = Touch.MinTarget),
                            shape = RoundedCornerShape(Radius.M)
                        ) {
                            Icon(Icons.Default.DeleteSweep, contentDescription = null, modifier = Modifier.size(IconSize.S))
                            Spacer(modifier = Modifier.width(Space.HS))
                            Text("回收站管理 (${uiState.trashedItems.size} 条待清理)", style = Type.BodyL)
                        }
                    }
                }
            }

            item(key = "danger_header") {
                Spacer(modifier = Modifier.height(Space.XXL))
                Text(
                    text = "危险操作",
                    style = Type.Label,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(start = Space.XS, bottom = Space.S)
                )
            }

            item(key = "danger_card") {
                SettingsAccordionCard(
                    title = "危险区域",
                    subtitle = "一键清空 · 立即执行硬件级物理自毁",
                    icon = Icons.Default.Warning,
                    iconTint = MaterialTheme.colorScheme.error,
                    isExpanded = expandDanger,
                    onToggle = { expandDanger = !expandDanger },
                    danger = true
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(Space.M)) {
                        Button(
                            onClick = { showConfirmClearDialog = true },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.errorContainer,
                                contentColor = MaterialTheme.colorScheme.onErrorContainer
                            ),
                            shape = RoundedCornerShape(Radius.M),
                            modifier = Modifier.fillMaxWidth().heightIn(min = Touch.MinTarget)
                        ) {
                            Text("一键清除全部 2FA 凭据", fontWeight = FontWeight.Bold, style = Type.BodyL)
                        }
                        SettingDivider()
                        Text(
                            text = "⚠ 此操作将注销硬件密钥并删除本地数据文件，不可恢复",
                            style = Type.BodyS,
                            fontWeight = FontWeight.Bold,
                            color = semantic.errorText
                        )
                        SelfDestructHoldButton(onHoldComplete = { showDestructInputDialog = true })
                    }
                }
            }
        }
    }

    if (showChangePinDialog) {
        ChangeMasterPinDialog(
            onDismiss = { showChangePinDialog = false },
            onSelfDestructed = onSelfDestructed,
            onChangePin = { cur, next, cb ->
                onChangeMasterPin(cur, next) { res ->
                    if (res is PinConfigResult.Ok) showSnack("主密码修改成功")
                    cb(res)
                }
            }
        )
    }

    if (showDuressDialog) {
        ConfigureDuressPinDialog(
            hasDuressPin = uiState.hasDuressPin,
            onDismiss = { showDuressDialog = false },
            onSelfDestructed = onSelfDestructed,
            onSetDuressPin = { master, duress, cb ->
                onSetDuressPin(master, duress) { res ->
                    if (res is PinConfigResult.Ok) showSnack("胁迫销毁密码已更新")
                    cb(res)
                }
            },
            onClearDuressPin = { master, cb ->
                onClearDuressPin(master) { res ->
                    if (res is PinConfigResult.Ok) showSnack("已关闭胁迫销毁密码")
                    cb(res)
                }
            }
        )
    }

    if (showAddWorkspaceDialog) {
        AddWorkspaceDialog(
            onDismiss = { showAddWorkspaceDialog = false },
            onAdd = { name ->
                onAddWorkspace(name)
                showAddWorkspaceDialog = false
                showSnack("已添加工作区「$name」")
            }
        )
    }

    workspaceToRename?.let { ws ->
        RenameWorkspaceDialog(
            workspace = ws,
            onDismiss = { workspaceToRename = null },
            onRename = { newName ->
                onRenameWorkspace(ws.id, newName)
                workspaceToRename = null
                showSnack("工作区已重命名")
            }
        )
    }

    workspaceToDelete?.let { ws ->
        val fallbackWs = uiState.workspaces.firstOrNull { it.id != ws.id }?.name ?: "默认工作区"
        val affectedCount = uiState.tokenCountByWorkspace[ws.id] ?: 0
        DeleteWorkspaceConfirmDialog(
            workspace = ws,
            affectedTokenCount = affectedCount,
            fallbackWorkspaceName = fallbackWs,
            onDismiss = { workspaceToDelete = null },
            onConfirm = {
                onDeleteWorkspace(ws.id)
                workspaceToDelete = null
                showSnack("工作区「${ws.name}」已删除")
            }
        )
    }

    if (showAddTagDialog) {
        CreateTagDialog(
            onDismiss = { showAddTagDialog = false },
            onCreate = { name, hex ->
                onAddTag(name, hex)
                showAddTagDialog = false
                showSnack("标签「$name」创建成功")
            }
        )
    }

    tagToDelete?.let { tag ->
        DeleteTagSettingConfirmDialog(
            tag = tag,
            onDismiss = { tagToDelete = null },
            onConfirm = {
                onDeleteTag(tag.id)
                tagToDelete = null
                showSnack("已删除标签：${tag.name}")
            }
        )
    }

    if (showTrashDialog) {
        TrashManagerDialog(
            items = uiState.trashedItems,
            onDismiss = { showTrashDialog = false },
            onRestore = { id ->
                onRestoreTrashToken(id)
                showSnack("已恢复凭据至主页")
            },
            onPermanentDelete = { id ->
                onPermanentDeleteTrashToken(id)
                showSnack("已永久删除该凭据")
            },
            onEmptyTrash = {
                onEmptyTrash()
                showSnack("回收站已清空")
            }
        )
    }

    if (showConfirmClearDialog) {
        ConfirmClearTokensDialog(
            onDismiss = { showConfirmClearDialog = false },
            onSelfDestructed = onSelfDestructed,
            onVerifyAndClear = { pin, cb ->
                onVerifyAndClearAll(pin) { res ->
                    if (res is SecurityLockManager.VerifyResult.Success) {
                        showSnack("已成功清空全部凭据")
                    }
                    cb(res)
                }
            }
        )
    }

    if (showDestructInputDialog) {
        SelfDestructInputDialog(
            onDismiss = { showDestructInputDialog = false },
            onConfirmed = {
                showDestructInputDialog = false
                showDestructCountdownDialog = true
            }
        )
    }

    if (showDestructCountdownDialog) {
        SelfDestructCountdownDialog(
            onDismiss = { showDestructCountdownDialog = false },
            onExecuteDestruct = {
                showDestructCountdownDialog = false
                onExecuteSelfDestruct()
            }
        )
    }
}
