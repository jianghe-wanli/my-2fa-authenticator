package com.f2a.authenticator.security

import android.app.Activity
import android.app.Application
import android.os.Bundle
import com.f2a.authenticator.data.model.AutoLockTimeout

class BackgroundLockMonitor(
    private val clock: Clock = SystemClockImpl
) : Application.ActivityLifecycleCallbacks {

    private var startedActivityCount = 0
    private var backgroundedAtElapsedMs: Long? = null
    private var suppressUntilElapsedMs: Long = 0L

    /**
     * 外部选择器（相册/SAF/BiometricPrompt）跳转前调用，豁免本次后台切出计入自动锁定（5 秒时间窗兜底，避免半屏选择器漏触发 onStop 后污染后续切后台）。
     */
    fun suppressNextBackgroundLock() {
        suppressUntilElapsedMs = clock.elapsedRealtimeMs() + SUPPRESS_WINDOW_MS
    }

    /**
     * 切回前台时判定是否已超过设定延时；若超时则返回 true 并消费本次标记。
     */
    fun checkAndConsumeShouldLock(timeout: AutoLockTimeout): Boolean {
        val leftAt = backgroundedAtElapsedMs ?: return false
        backgroundedAtElapsedMs = null
        if (timeout == AutoLockTimeout.NEVER) return false
        val elapsedInBackgroundMs = (clock.elapsedRealtimeMs() - leftAt).coerceAtLeast(0L)
        return elapsedInBackgroundMs >= timeout.seconds * 1000L
    }

    fun resetBackgroundTimer() {
        backgroundedAtElapsedMs = null
        suppressUntilElapsedMs = 0L
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit

    override fun onActivityStarted(activity: Activity) {
        startedActivityCount++
    }

    override fun onActivityResumed(activity: Activity) {
        // 若外部选择器以半屏/浮层形式运行而未触发 onActivityStopped，恢复前台时立即回收豁免窗口
        suppressUntilElapsedMs = 0L
    }

    override fun onActivityPaused(activity: Activity) = Unit

    override fun onActivityStopped(activity: Activity) {
        startedActivityCount = (startedActivityCount - 1).coerceAtLeast(0)
        // 配置变更（旋转/深浅色切换）触发的重建不计入后台切出
        if (startedActivityCount == 0 && !activity.isChangingConfigurations) {
            val nowElapsed = clock.elapsedRealtimeMs()
            if (nowElapsed <= suppressUntilElapsedMs) {
                suppressUntilElapsedMs = 0L
                backgroundedAtElapsedMs = null
            } else {
                suppressUntilElapsedMs = 0L
                backgroundedAtElapsedMs = nowElapsed
            }
        }
    }

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

    override fun onActivityDestroyed(activity: Activity) = Unit

    private companion object {
        const val SUPPRESS_WINDOW_MS = 5_000L
    }
}
