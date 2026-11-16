package com.f2a.authenticator

import android.app.Application
import com.f2a.authenticator.di.AppContainer
import com.f2a.authenticator.di.DefaultAppContainer

class My2FAApplication : Application() {

    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = DefaultAppContainer(this)
        registerActivityLifecycleCallbacks(container.backgroundLockMonitor)
    }
}
