package com.f2a.authenticator.utils

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * 隐私防窥：剪贴板自动限时抹除器。
 * - 不在静态内存保留明文（仅保留 SHA-256 摘要用于比对是否仍为本应用复制的敏感文本）
 * - 为 ClipData 设置 Android 13+ EXTRA_IS_SENSITIVE 掩码标记
 * - 提供实时 remainingSeconds 倒计时 StateFlow 与一键 clearNow() 立即清空能力
 * - 支持在 onWindowFocusChanged(true) 时执行 clearIfExpiredOnWindowFocus 兜底清理
 */
object ClipboardGuard {

    private const val EXTRA_IS_SENSITIVE_COMPAT = "android.content.extra.IS_SENSITIVE"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var clearJob: Job? = null

    private val _remainingSeconds = MutableStateFlow(0)
    val remainingSeconds: StateFlow<Int> = _remainingSeconds.asStateFlow()

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
            _remainingSeconds.value = 0
            return
        }

        val digest = sha256(text)
        expectedDigest = digest
        expiresAtElapsedMs = SystemClock.elapsedRealtime() + autoClearSeconds * 1000L
        _remainingSeconds.value = autoClearSeconds

        clearJob = scope.launch {
            while (true) {
                delay(1000L)
                val deadline = expiresAtElapsedMs ?: break
                val leftMs = deadline - SystemClock.elapsedRealtime()
                if (leftMs <= 0L) break
                _remainingSeconds.value = ((leftMs + 999L) / 1000L).toInt().coerceAtLeast(1)
            }
            _remainingSeconds.value = 0
            tryClearIfMatching(clipboard, digest)
        }
    }

    /**
     * 立即清空本应用当前管理的系统剪贴板敏感内容（如用户点击“立即清除”或触发胁迫/自毁）。
     */
    fun clearNow(context: Context) {
        clearJob?.cancel()
        clearJob = null
        val digest = expectedDigest
        expectedDigest = null
        expiresAtElapsedMs = null
        _remainingSeconds.value = 0

        val appContext = context.applicationContext ?: context
        val performClear = {
            try {
                val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                if (clipboard != null) {
                    if (digest != null) {
                        val currentClip = try {
                            clipboard.primaryClip
                        } catch (_: Exception) {
                            null
                        }
                        if (currentClip == null) {
                            // 后台无焦点/自毁场景无法比对时直接尝试清除系统剪贴板
                            clearSystemClipboard(clipboard)
                        } else if (currentClip.itemCount > 0) {
                            val currentText = currentClip.getItemAt(0).text?.toString()
                            if (currentText != null && MessageDigest.isEqual(sha256(currentText), digest)) {
                                clearSystemClipboard(clipboard)
                            }
                        }
                    } else {
                        clearSystemClipboard(clipboard)
                    }
                }
            } catch (_: Exception) {
            }
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            performClear()
        } else {
            try {
                scope.launch { performClear() }
            } catch (_: Exception) {
                performClear()
            }
        }
    }

    /**
     * 窗口重新获取输入焦点时（onWindowFocusChanged(true)）检查超期剪贴板摘要，
     * 解决 Android 10-15 在 onResume() 时窗口尚未获焦导致 primaryClip 读取失败的问题。
     */
    fun clearIfExpiredOnWindowFocus(context: Context) {
        val deadline = expiresAtElapsedMs ?: return
        val digest = expectedDigest ?: return
        if (SystemClock.elapsedRealtime() < deadline) return

        _remainingSeconds.value = 0
        val appContext = context.applicationContext ?: context
        val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        tryClearIfMatching(clipboard, digest)
    }

    /**
     * 保留向后兼容入口，转发至窗口焦点兜底清理逻辑。
     */
    fun clearIfExpiredOnResume(context: Context) {
        clearIfExpiredOnWindowFocus(context)
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
        _remainingSeconds.value = 0
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
