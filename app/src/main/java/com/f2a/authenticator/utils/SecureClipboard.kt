package com.f2a.authenticator.utils

import android.content.Context

/**
 * 剪贴板统一收口：所有敏感复制（验证码、迁移链接、备份密文）均走此处。
 */
object SecureClipboard {

    private const val MAX_SENSITIVE_CLEAR_SECONDS = 30

    fun copy(context: Context, text: String, clearSeconds: Int) {
        ClipboardGuard.copyWithAutoClear(context, text, autoClearSeconds = clearSeconds)
    }

    /**
     * 高敏感内容（备份密文、批量迁移 URI 等）：强制不超过 30 秒自动清除。
     */
    fun copySensitive(context: Context, text: String, clearSeconds: Int) {
        val effectiveSeconds = if (clearSeconds <= 0) {
            MAX_SENSITIVE_CLEAR_SECONDS
        } else {
            minOf(clearSeconds, MAX_SENSITIVE_CLEAR_SECONDS)
        }
        ClipboardGuard.copyWithAutoClear(context, text, autoClearSeconds = effectiveSeconds)
    }
}
