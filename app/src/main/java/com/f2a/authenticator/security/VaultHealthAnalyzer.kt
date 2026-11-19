package com.f2a.authenticator.security

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.AutoLockTimeout
import com.f2a.authenticator.data.model.VaultPreferences
import com.f2a.authenticator.totp.OtpEngine
import java.util.Locale

enum class HealthSeverity {
    OK,
    WARNING,
    CRITICAL
}

data class VaultHealthItem(
    val id: String,
    val title: String,
    val detail: String,
    val severity: HealthSeverity,
    val actionKey: String? = null
)

data class VaultHealthReport(
    val score: Int,
    val items: List<VaultHealthItem>,
    val duplicateCount: Int,
    val corruptedCount: Int,
    val weakSecretCount: Int,
    val backupOverdue: Boolean,
    val daysSinceLastBackup: Int?
)

/**
 * 纯 Kotlin 离线保险库安全体检分析引擎：
 * - 零网络依赖，完全基于本地令牌元数据、密钥熵/重复度与安全配置生成 0~100 安全评分与可执行修复建议。
 */
object VaultHealthAnalyzer {

    private const val DAY_MS = 24L * 60L * 60L * 1000L
    private const val BACKUP_OVERDUE_DAYS = 30
    private const val MIN_RECOMMENDED_SECRET_BYTES = 10 // 80 bits (RFC 4226 最低推荐)

    fun analyze(
        tokens: List<AuthToken>,
        preferences: VaultPreferences,
        isDuressConfigured: Boolean,
        isBiometricEnabled: Boolean,
        nowMs: Long = System.currentTimeMillis(),
        isFlagSecureEnabled: Boolean = true,
        clipboardClearSeconds: Int = 45
    ): VaultHealthReport {
        val activeTokens = tokens.filter { it.deletedAt == null }
        val corruptedCount = activeTokens.count { it.secretInvalid }
        val validTokens = activeTokens.filter { !it.secretInvalid }

        val secretCounts = HashMap<String, Int>()
        var weakSecretCount = 0

        for (token in validTokens) {
            val normalizedSecret = normalizeBase32(token.secret)
            val decodedBytes = OtpEngine.decodeBase32(normalizedSecret)
            if (decodedBytes.size < MIN_RECOMMENDED_SECRET_BYTES) {
                weakSecretCount++
            }
            if (normalizedSecret.isNotEmpty()) {
                secretCounts[normalizedSecret] = (secretCounts[normalizedSecret] ?: 0) + 1
            }
        }

        val duplicateCount = secretCounts.values.sumOf { (it - 1).coerceAtLeast(0) }

        val daysSinceLastBackup = preferences.lastBackupAtMillis?.let { lastTs ->
            ((nowMs - lastTs).coerceAtLeast(0L) / DAY_MS).toInt()
        }
        val backupOverdue = activeTokens.isNotEmpty() &&
            (daysSinceLastBackup == null || daysSinceLastBackup >= BACKUP_OVERDUE_DAYS)
        val unbackedNewTokens = if (preferences.lastBackupAtMillis != null) {
            (activeTokens.size - preferences.lastBackupTokenCount).coerceAtLeast(0)
        } else {
            0
        }

        var score = 100
        val items = ArrayList<VaultHealthItem>()

        // 1. 损坏凭据检测
        if (corruptedCount > 0) {
            score -= minOf(35, corruptedCount * 15)
            items.add(
                VaultHealthItem(
                    id = "corrupted_tokens",
                    title = "存在 $corruptedCount 个损坏凭据",
                    detail = "部分密钥无法通过硬件 KeyStore 解密，建议核查并重新导入。",
                    severity = HealthSeverity.CRITICAL,
                    actionKey = "corrupted"
                )
            )
        } else {
            items.add(
                VaultHealthItem(
                    id = "corrupted_tokens",
                    title = "硬件加密凭据完整",
                    detail = "所有活跃 2FA 密钥均可正常受硬件主密钥保护与解密。",
                    severity = HealthSeverity.OK
                )
            )
        }

        // 2. 防截屏与录屏保护
        if (!isFlagSecureEnabled) {
            score -= 20
            items.add(
                VaultHealthItem(
                    id = "flag_secure",
                    title = "防截屏保护 (FLAG_SECURE) 已关闭",
                    detail = "多任务卡片与后台录屏可能捕获验证码明文，建议立即开启。",
                    severity = HealthSeverity.CRITICAL,
                    actionKey = "flag_secure"
                )
            )
        } else {
            items.add(
                VaultHealthItem(
                    id = "flag_secure",
                    title = "防截屏与多任务遮罩已开启",
                    detail = "系统截屏、录屏及多任务快照均已禁止读取保险库画面。",
                    severity = HealthSeverity.OK
                )
            )
        }

        // 3. 后台自动锁定超时
        if (preferences.autoLockTimeout == AutoLockTimeout.NEVER) {
            score -= 20
            items.add(
                VaultHealthItem(
                    id = "auto_lock",
                    title = "后台自动锁定已关闭",
                    detail = "切出应用后明文密钥将持续驻留内存，建议设为「立即」或「30 秒」。",
                    severity = HealthSeverity.CRITICAL,
                    actionKey = "autolock"
                )
            )
        } else {
            items.add(
                VaultHealthItem(
                    id = "auto_lock",
                    title = "后台自动锁定已启用",
                    detail = if (preferences.autoLockTimeout == AutoLockTimeout.IMMEDIATE) {
                        "切离应用时立即清空内存明文并上锁。"
                    } else {
                        "离开应用 ${preferences.autoLockTimeout.seconds} 秒后自动锁定。"
                    },
                    severity = HealthSeverity.OK
                )
            )
        }

        // 4. 加密灾备提醒
        if (backupOverdue) {
            score -= 15
            val detail = if (daysSinceLastBackup == null) {
                "当前共有 ${activeTokens.size} 个凭据尚未进行过 .jdf2 端到端加密灾备，建议尽快导出保存。"
            } else {
                "距离上次安全备份已过去 $daysSinceLastBackup 天，建议重新导出最新 .jdf2 加密备份。"
            }
            items.add(
                VaultHealthItem(
                    id = "backup_status",
                    title = if (daysSinceLastBackup == null) "尚未创建加密备份" else "加密备份已超期",
                    detail = detail,
                    severity = HealthSeverity.WARNING,
                    actionKey = "backup"
                )
            )
        } else if (unbackedNewTokens > 0) {
            score -= 5
            items.add(
                VaultHealthItem(
                    id = "backup_status",
                    title = "有 $unbackedNewTokens 个新增凭据未纳入上次备份",
                    detail = "上次备份距今 ${daysSinceLastBackup ?: 0} 天，建议更新一份全量加密备份。",
                    severity = HealthSeverity.WARNING,
                    actionKey = "backup"
                )
            )
        } else if (activeTokens.isNotEmpty()) {
            items.add(
                VaultHealthItem(
                    id = "backup_status",
                    title = "加密灾备状态良好",
                    detail = "上次 .jdf2 安全备份距今 ${daysSinceLastBackup ?: 0} 天。",
                    severity = HealthSeverity.OK
                )
            )
        }

        // 5. 胁迫销毁密码
        if (!isDuressConfigured) {
            score -= 10
            items.add(
                VaultHealthItem(
                    id = "duress_pin",
                    title = "未配置胁迫销毁密码",
                    detail = "配置独立胁迫码可在受迫解锁时静默抹除本地密钥并进入空库伪装态。",
                    severity = HealthSeverity.WARNING,
                    actionKey = "duress"
                )
            )
        } else {
            items.add(
                VaultHealthItem(
                    id = "duress_pin",
                    title = "胁迫销毁防线已就绪",
                    detail = "已配置独立于主密码的静默抹除胁迫码。",
                    severity = HealthSeverity.OK
                )
            )
        }

        // 6. 剪贴板自动清除
        if (clipboardClearSeconds <= 0) {
            score -= 10
            items.add(
                VaultHealthItem(
                    id = "clipboard_clear",
                    title = "剪贴板自动清除已关闭",
                    detail = "复制的动态验证码会保留在系统剪贴板中，建议开启 30~45 秒自动清除。",
                    severity = HealthSeverity.WARNING,
                    actionKey = "clipboard"
                )
            )
        } else {
            items.add(
                VaultHealthItem(
                    id = "clipboard_clear",
                    title = "剪贴板限时清理已启用（${clipboardClearSeconds}s）",
                    detail = "复制内容已附加系统敏感标记并在设定时间后尝试自动抹除。",
                    severity = HealthSeverity.OK
                )
            )
        }

        // 7. 重复 Base32 密钥检测
        if (duplicateCount > 0) {
            score -= 10
            items.add(
                VaultHealthItem(
                    id = "duplicate_secrets",
                    title = "检测到 $duplicateCount 处重复密钥",
                    detail = "多个账号使用了相同的 Base32 种子，建议排查是否为重复导入。",
                    severity = HealthSeverity.WARNING,
                    actionKey = "duplicates"
                )
            )
        }

        // 8. 弱熵密钥检测
        if (weakSecretCount > 0) {
            score -= 10
            items.add(
                VaultHealthItem(
                    id = "weak_secrets",
                    title = "存在 $weakSecretCount 个低熵短密钥 (<80 bit)",
                    detail = "部分密钥字节长度低于 RFC 4226 建议的 10 字节下限，请留意服务商安全强度。",
                    severity = HealthSeverity.WARNING,
                    actionKey = "weak_secrets"
                )
            )
        }

        // 9. 防窥模式与生物识别信息项（不扣基础分，正向提示）
        items.add(
            if (preferences.privacyMaskEnabled) {
                VaultHealthItem(
                    id = "privacy_mask",
                    title = "防肩窥默认打码已开启",
                    detail = "列表默认隐藏验证码明文，点击后临时揭示。",
                    severity = HealthSeverity.OK
                )
            } else {
                VaultHealthItem(
                    id = "privacy_mask",
                    title = "可选：开启列表默认打码防肩窥",
                    detail = "在公共场所查看保险库时可默认遮罩验证码数字。",
                    severity = HealthSeverity.OK,
                    actionKey = "privacy_mask"
                )
            }
        )

        if (isBiometricEnabled) {
            items.add(
                VaultHealthItem(
                    id = "biometric",
                    title = "强生物识别快捷解锁已开启",
                    detail = "已限定 Class 3 (BIOMETRIC_STRONG) 生物特征验证。",
                    severity = HealthSeverity.OK
                )
            )
        }

        val sortedItems = items.sortedBy {
            when (it.severity) {
                HealthSeverity.CRITICAL -> 0
                HealthSeverity.WARNING -> 1
                HealthSeverity.OK -> 2
            }
        }

        return VaultHealthReport(
            score = score.coerceIn(0, 100),
            items = sortedItems,
            duplicateCount = duplicateCount,
            corruptedCount = corruptedCount,
            weakSecretCount = weakSecretCount,
            backupOverdue = backupOverdue,
            daysSinceLastBackup = daysSinceLastBackup
        )
    }

    private fun normalizeBase32(secret: String): String =
        secret.trim()
            .replace("-", "")
            .replace(" ", "")
            .replace("\n", "")
            .replace("\r", "")
            .replace("=", "")
            .uppercase(Locale.US)
}
