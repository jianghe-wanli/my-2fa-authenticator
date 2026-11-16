package com.f2a.authenticator.utils

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * 隐私防窥：剪贴板自动限时抹除器。
 * - 不在静态内存保留明文（仅保留 SHA-256 摘要用于比对是否仍为本应用复制的敏感文本）
 * - 为 ClipData 设置 Android 13+ EXTRA_IS_SENSITIVE 掩码标记
 * - API 28+ 使用原生 clearPrimaryClip() 清除，配合前台恢复兜底擦除应对 Android 10+ 后台剪贴板读取限制
 */
object ClipboardGuard {

    private const val EXTRA_IS_SENSITIVE_COMPAT = "android.content.extra.IS_SENSITIVE"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var clearJob: Job? = null

    @Volatile
    private var expectedDigest: ByteArray? = null

    @Volatile
    private var expiresAtElapsedMs: Long? = null

    /**
     * @param autoClearSeconds 自动清除秒数；<=0 表示不自动清除
     */
    fun copyWithAutoClear(context: Context, text: String, autoClearSeconds: Int = 45) {
        val appContext = context.applicationContext ?: context
        val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return

        val clip = ClipData.newPlainText("2FA Code", text).apply {
            val extras = PersistableBundle().apply {
                val key = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    ClipDescription.EXTRA_IS_SENSITIVE
                } else {
                    EXTRA_IS_SENSITIVE_COMPAT
                }
                putBoolean(key, true)
            }
            description.extras = extras
        }
        clipboard.setPrimaryClip(clip)

        clearJob?.cancel()
        if (autoClearSeconds <= 0) {
            clearJob = null
            expectedDigest = null
            expiresAtElapsedMs = null
            return
        }

        val digest = sha256(text)
        expectedDigest = digest
        expiresAtElapsedMs = SystemClock.elapsedRealtime() + autoClearSeconds * 1000L

        clearJob = scope.launch {
            delay(autoClearSeconds * 1000L)
            tryClearIfMatching(clipboard, digest)
        }
    }

    /**
     * 前台恢复时检查已超期的剪贴板摘要，兜底清理 Android 10+ 后台无焦点导致未能及时擦除的敏感项。
     */
    fun clearIfExpiredOnResume(context: Context) {
        val deadline = expiresAtElapsedMs ?: return
        val digest = expectedDigest ?: return
        if (SystemClock.elapsedRealtime() < deadline) return

        val appContext = context.applicationContext ?: context
        val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        tryClearIfMatching(clipboard, digest)
    }

    private fun tryClearIfMatching(clipboard: ClipboardManager, targetDigest: ByteArray) {
        val currentClip = try {
            clipboard.primaryClip
        } catch (_: Exception) {
            null
        } ?: return

        if (currentClip.itemCount > 0) {
            val currentText = currentClip.getItemAt(0).text?.toString()
            if (currentText != null && MessageDigest.isEqual(sha256(currentText), targetDigest)) {
                clearSystemClipboard(clipboard)
            }
        }
        expectedDigest = null
        expiresAtElapsedMs = null
    }

    private fun clearSystemClipboard(clipboard: ClipboardManager) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }

    private fun sha256(text: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(StandardCharsets.UTF_8))
}
