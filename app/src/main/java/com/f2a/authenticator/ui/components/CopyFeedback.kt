package com.f2a.authenticator.ui.components

import androidx.compose.material3.SnackbarHostState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * 复制反馈统一 Snackbar 工具（解耦 SecurityLockManager，直接消费 clipboardClearSeconds）。
 */
object CopyFeedback {

    fun buildMessage(clipboardClearSeconds: Int): String {
        return if (clipboardClearSeconds <= 0) {
            "已复制（自动清除已关闭）"
        } else {
            "已复制 · $clipboardClearSeconds 秒后自动清除"
        }
    }

    fun show(
        snackbarHostState: SnackbarHostState,
        scope: CoroutineScope,
        clipboardClearSeconds: Int
    ) {
        scope.launch {
            snackbarHostState.currentSnackbarData?.dismiss()
            snackbarHostState.showSnackbar(buildMessage(clipboardClearSeconds))
        }
    }
}
