package com.f2a.authenticator.di

import android.content.Context
import android.content.pm.ApplicationInfo
import com.f2a.authenticator.crypto.KeyStoreManager
import com.f2a.authenticator.crypto.SecretCipher
import com.f2a.authenticator.data.local.TokenRepository
import com.f2a.authenticator.data.local.TokenVaultRepository
import com.f2a.authenticator.data.local.VaultPreferencesRepository
import com.f2a.authenticator.data.local.VaultPreferencesStore
import com.f2a.authenticator.security.BackgroundLockMonitor
import com.f2a.authenticator.security.Clock
import com.f2a.authenticator.security.SecurityLockManager
import com.f2a.authenticator.security.SystemClockImpl

interface AppContainer {
    val clock: Clock
    val secretCipher: SecretCipher
    val tokenRepository: TokenVaultRepository
    val preferencesRepository: VaultPreferencesRepository
    val securityLockManager: SecurityLockManager
    val backgroundLockMonitor: BackgroundLockMonitor
}

class DefaultAppContainer(context: Context) : AppContainer {

    private val appContext: Context = context.applicationContext ?: context
    private val isDebugBuild: Boolean =
        (appContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    override val clock: Clock = SystemClockImpl
    override val secretCipher: SecretCipher = KeyStoreManager

    override val tokenRepository: TokenVaultRepository by lazy {
        TokenRepository(
            context = appContext,
            cipher = secretCipher,
            clock = clock,
            isDebugBuild = isDebugBuild
        )
    }

    override val preferencesRepository: VaultPreferencesRepository by lazy {
        VaultPreferencesStore(appContext)
    }

    override val securityLockManager: SecurityLockManager by lazy {
        SecurityLockManager(
            context = appContext,
            clock = clock,
            cipher = secretCipher
        )
    }

    override val backgroundLockMonitor: BackgroundLockMonitor by lazy {
        BackgroundLockMonitor(clock = clock)
    }
}
