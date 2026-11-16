package com.f2a.authenticator.security

interface Clock {
    fun elapsedRealtimeMs(): Long
    fun currentTimeMillis(): Long
}

object SystemClockImpl : Clock {
    override fun elapsedRealtimeMs(): Long = android.os.SystemClock.elapsedRealtime()
    override fun currentTimeMillis(): Long = System.currentTimeMillis()
}
