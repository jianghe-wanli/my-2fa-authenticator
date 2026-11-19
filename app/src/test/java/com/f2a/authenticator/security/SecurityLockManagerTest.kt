package com.f2a.authenticator.security

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import com.f2a.authenticator.crypto.SecretCipher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@OptIn(ExperimentalCoroutinesApi::class)
class SecurityLockManagerTest {

    private class FakeClock(
        var elapsed: Long = 100_000L,
        var wall: Long = 1_700_000_000_000L
    ) : Clock {
        override fun elapsedRealtimeMs(): Long = elapsed
        override fun currentTimeMillis(): Long = wall
    }

    private class FakeSecretCipher : SecretCipher {
        var destroyed = false
        override fun encrypt(plainText: String) = SecretCipher.EncryptResult.Ok(plainText)
        override fun decrypt(cipherTextBase64: String) = SecretCipher.DecryptResult.Ok(cipherTextBase64)
        override fun destroyMasterKey() {
            destroyed = true
        }
    }

    private class InMemorySharedPreferences : SharedPreferences {
        private val data = LinkedHashMap<String, Any?>()

        override fun getAll(): MutableMap<String, *> = LinkedHashMap(data)
        override fun getString(key: String?, defValue: String?): String? =
            (data[key] as? String) ?: defValue

        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            (data[key] as? Set<String>)?.toMutableSet() ?: defValues

        override fun getInt(key: String?, defValue: Int): Int =
            (data[key] as? Int) ?: defValue

        override fun getLong(key: String?, defValue: Long): Long =
            (data[key] as? Long) ?: defValue

        override fun getFloat(key: String?, defValue: Float): Float =
            (data[key] as? Float) ?: defValue

        override fun getBoolean(key: String?, defValue: Boolean): Boolean =
            (data[key] as? Boolean) ?: defValue

        override fun contains(key: String?): Boolean = data.containsKey(key)

        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = LinkedHashMap<String, Any?>()
            private var clearRequested = false

            override fun putString(key: String?, value: String?) = apply {
                if (key != null) pending[key] = value
            }

            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {
                if (key != null) pending[key] = values?.toSet()
            }

            override fun putInt(key: String?, value: Int) = apply {
                if (key != null) pending[key] = value
            }

            override fun putLong(key: String?, value: Long) = apply {
                if (key != null) pending[key] = value
            }

            override fun putFloat(key: String?, value: Float) = apply {
                if (key != null) pending[key] = value
            }

            override fun putBoolean(key: String?, value: Boolean) = apply {
                if (key != null) pending[key] = value
            }

            override fun remove(key: String?) = apply {
                if (key != null) pending[key] = REMOVE_SENTINEL
            }

            override fun clear() = apply {
                clearRequested = true
                pending.clear()
            }

            override fun commit(): Boolean {
                apply()
                return true
            }

            override fun apply() {
                if (clearRequested) {
                    data.clear()
                }
                for ((k, v) in pending) {
                    if (v === REMOVE_SENTINEL) {
                        data.remove(k)
                    } else {
                        data[k] = v
                    }
                }
            }
        }

        override fun registerOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) = Unit

        override fun unregisterOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) = Unit

        private companion object {
            val REMOVE_SENTINEL = Any()
        }
    }

    private class FakeContext(private val tempDataDir: File) : ContextWrapper(null) {
        val prefsMap = LinkedHashMap<String, InMemorySharedPreferences>()

        override fun getApplicationContext(): Context = this

        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
            prefsMap.getOrPut(name ?: "default") { InMemorySharedPreferences() }

        override fun deleteSharedPreferences(name: String?): Boolean {
            val removed = prefsMap.remove(name ?: "default")
            removed?.edit()?.clear()?.commit()
            return removed != null
        }

        override fun getApplicationInfo(): ApplicationInfo = ApplicationInfo().apply {
            dataDir = tempDataDir.absolutePath
        }

        override fun getFilesDir(): File = File(tempDataDir, "files").apply { mkdirs() }
    }

    private fun createEnv(): Triple<SecurityLockManager, FakeClock, FakeSecretCipher> {
        val tempDir = Files.createTempDirectory("f2a-sec-test").toFile()
        tempDir.deleteOnExit()
        val context = FakeContext(tempDir)
        val clock = FakeClock()
        val cipher = FakeSecretCipher()
        val manager = SecurityLockManager(
            context = context,
            clock = clock,
            cipher = cipher,
            cryptoDispatcher = UnconfinedTestDispatcher(),
            ioDispatcher = UnconfinedTestDispatcher()
        )
        return Triple(manager, clock, cipher)
    }

    @Test
    fun setupPin_rejectsInvalidWeakAndSameAsDuress() = runTest {
        val (manager, _, _) = createEnv()

        assertEquals(PinConfigResult.InvalidFormat, manager.setupPin("12345"))
        assertEquals(PinConfigResult.InvalidFormat, manager.setupPin("12a456"))
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("111111"))
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("123456"))
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("654321"))
        assertEquals(PinConfigResult.SameAsCounterpart, manager.setupPin("258013", "258013"))
        assertFalse(manager.isPinConfigured())

        assertEquals(PinConfigResult.Ok, manager.setupPin("258013", "917364"))
        assertTrue(manager.isPinConfigured())
        assertTrue(manager.hasDuressPin())
    }

    @Test
    fun changeMasterPin_andClearDuressPin_enforceAuthAndCollisionCheck() = runTest {
        val (manager, _, _) = createEnv()
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013", "917364"))

        // 改密时新密码不得与当前胁迫码相同
        assertEquals(PinConfigResult.SameAsCounterpart, manager.changeMasterPin("258013", "917364"))

        // 错误当前密码应被拒绝并计数
        val badAuth = manager.changeMasterPin("000999", "482715")
        assertTrue(badAuth is PinConfigResult.AuthFailed)
        assertEquals(SecurityLockManager.VerifyResult.WrongPin(4), (badAuth as PinConfigResult.AuthFailed).verifyResult)

        // 正确改密成功，旧主密码失效、新主密码有效
        assertEquals(PinConfigResult.Ok, manager.changeMasterPin("258013", "482715"))
        assertTrue(manager.verifyPin("258013") is SecurityLockManager.VerifyResult.WrongPin)
        assertEquals(SecurityLockManager.VerifyResult.Success, manager.verifyPin("482715"))

        // 清除胁迫码后原胁迫码按普通错误密码处理
        assertEquals(PinConfigResult.Ok, manager.clearDuressPin("482715"))
        assertFalse(manager.hasDuressPin())
        assertTrue(manager.verifyPin("917364") is SecurityLockManager.VerifyResult.WrongPin)
    }

    @Test
    fun setDuressPin_rejectsSameAsMaster() = runTest {
        val (manager, _, _) = createEnv()
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013"))

        assertEquals(PinConfigResult.SameAsCounterpart, manager.setDuressPin("258013", "258013"))
        assertFalse(manager.hasDuressPin())

        assertEquals(PinConfigResult.Ok, manager.setDuressPin("258013", "741852"))
        assertTrue(manager.hasDuressPin())
    }

    @Test
    fun duressPin_triggersSilentDestructAndClearsCipher() = runTest {
        val tempDir = Files.createTempDirectory("f2a-duress-test").toFile()
        tempDir.deleteOnExit()
        val context = FakeContext(tempDir)
        context.getSharedPreferences("my_2fa_secure_store", Context.MODE_PRIVATE)
            .edit().putString("tokens_data", "secret").commit()
        context.getSharedPreferences("my_2fa_vault_prefs", Context.MODE_PRIVATE)
            .edit().putString("vault_preferences_json", "{}").commit()

        val cipher = FakeSecretCipher()
        val manager = SecurityLockManager(
            context = context,
            clock = FakeClock(),
            cipher = cipher,
            cryptoDispatcher = UnconfinedTestDispatcher()
        )
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013", "741852"))

        val result = manager.verifyPin("741852")
        assertEquals(SecurityLockManager.VerifyResult.DuressTriggered, result)
        assertTrue(cipher.destroyed)
        assertFalse(manager.isPinConfigured())
        assertFalse(context.prefsMap.containsKey("my_2fa_secure_store"))
        assertFalse(context.prefsMap.containsKey("my_2fa_vault_prefs"))
    }

    @Test
    fun lockout_usesMonotonicClock_immuneToWallClockTampering() = runTest {
        val (manager, clock, _) = createEnv()
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013"))

        assertEquals(SecurityLockManager.VerifyResult.WrongPin(4), manager.verifyPin("999001"))
        assertEquals(SecurityLockManager.VerifyResult.WrongPin(3), manager.verifyPin("999002"))
        val locked = manager.verifyPin("999003")
        assertEquals(SecurityLockManager.VerifyResult.LockedOut(30L), locked)

        // 篡改系统墙钟向前拨 10 小时，单调时钟冷却不受影响
        clock.wall += 10L * 3600L * 1000L
        assertEquals(30L, manager.getLockoutRemainingSeconds())
        assertTrue(manager.verifyPin("258013") is SecurityLockManager.VerifyResult.LockedOut)

        // 推进单调时钟 30 秒后解除冷却
        clock.elapsed += 30_000L
        assertEquals(0L, manager.getLockoutRemainingSeconds())
        assertEquals(SecurityLockManager.VerifyResult.Success, manager.verifyPin("258013"))
    }

    @Test
    fun lockout_survivesDeviceRebootByPreservingRemainingCooldown() = runTest {
        val (manager, clock, _) = createEnv()
        clock.elapsed = 500_000L
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013"))

        manager.verifyPin("999001")
        manager.verifyPin("999002")
        assertEquals(SecurityLockManager.VerifyResult.LockedOut(30L), manager.verifyPin("999003"))

        // 经过 10 秒，剩余 20 秒冷却
        clock.elapsed += 10_000L
        assertEquals(20L, manager.getLockoutRemainingSeconds())

        // 模拟设备重启：elapsedRealtime 归零重置为 1_500ms（小于上次记录的 510_000ms）
        clock.elapsed = 1_500L
        assertEquals(20L, manager.getLockoutRemainingSeconds())

        // 重启后需继续等待满 20 秒才能解锁
        clock.elapsed += 19_000L
        assertEquals(1L, manager.getLockoutRemainingSeconds())
        assertTrue(manager.verifyPin("258013") is SecurityLockManager.VerifyResult.LockedOut)

        clock.elapsed += 1_000L
        assertEquals(0L, manager.getLockoutRemainingSeconds())
        assertEquals(SecurityLockManager.VerifyResult.Success, manager.verifyPin("258013"))
    }

    @Test
    fun maxAttempts_clampedTo3And10_andTriggersSelfDestruct() = runTest {
        val (manager, clock, cipher) = createEnv()
        manager.setMaxAttempts(0)
        assertEquals(3, manager.getMaxAttempts())

        manager.setMaxAttempts(99)
        assertEquals(10, manager.getMaxAttempts())

        manager.setMaxAttempts(3)
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013"))

        assertEquals(SecurityLockManager.VerifyResult.WrongPin(2), manager.verifyPin("999001"))
        assertEquals(SecurityLockManager.VerifyResult.WrongPin(1), manager.verifyPin("999002"))
        clock.elapsed += 1000L
        val destructed = manager.verifyPin("999003")
        assertEquals(SecurityLockManager.VerifyResult.SelfDestructed, destructed)
        assertTrue(cipher.destroyed)
        assertFalse(manager.isPinConfigured())
    }

    @Test
    fun missingPinAnomaly_detectedWhenEncryptedTokensExistOrConfigFlagRemains() = runTest {
        val tempDir = Files.createTempDirectory("f2a-anomaly-test").toFile()
        tempDir.deleteOnExit()
        val context = FakeContext(tempDir)
        val manager = SecurityLockManager(
            context = context,
            clock = FakeClock(),
            cipher = FakeSecretCipher(),
            cryptoDispatcher = UnconfinedTestDispatcher()
        )

        // 全新安装：无 PIN 且无加密令牌，不视为异常
        assertFalse(manager.isPinMissingAnomaly(hasStoredEncryptedTokens = false))

        // 若删掉了 security_vault_guard.xml 但磁盘仍有加密令牌：立即告警
        assertTrue(manager.isPinMissingAnomaly(hasStoredEncryptedTokens = true))

        // 配置 PIN 后正常
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013"))
        assertFalse(manager.isPinMissingAnomaly(hasStoredEncryptedTokens = true))

        // 模拟仅篡改删除了 PIN 哈希字段但保留了其他配置：仍能检出异常
        context.getSharedPreferences("security_vault_guard", Context.MODE_PRIVATE)
            .edit()
            .remove("vault_master_pin_hash")
            .apply()
        assertFalse(manager.isPinConfigured())
        assertTrue(manager.isPinMissingAnomaly(hasStoredEncryptedTokens = false))
    }

    @Test
    fun setupPin_rejectsExtendedWeakPatterns_whileAllowingExistingValidPins() = runTest {
        val (manager, _, _) = createEnv()
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("112233"))
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("121212"))
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("123123"))
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("111222"))
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("123321"))
        assertEquals(PinConfigResult.WeakPin, manager.setupPin("000001"))

        assertEquals(PinConfigResult.Ok, manager.setupPin("258013", "741852"))
        assertEquals(SecurityLockManager.VerifyResult.Success, manager.verifyPin("258013"))
    }

    @Test
    fun verifyPin_remainsCompatibleWithLegacy100kHashFormat() = runTest {
        val tempDir = Files.createTempDirectory("f2a-legacy-pin-test").toFile()
        tempDir.deleteOnExit()
        val context = FakeContext(tempDir)

        val salt = ByteArray(32) { it.toByte() }
        val spec = PBEKeySpec("482715".toCharArray(), salt, 100_000, 256)
        val hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        spec.clearPassword()

        context.getSharedPreferences("security_vault_guard", Context.MODE_PRIVATE)
            .edit()
            .putString("vault_master_pin_salt", Base64.getEncoder().encodeToString(salt))
            .putString("vault_master_pin_hash", Base64.getEncoder().encodeToString(hash))
            .putBoolean("vault_pin_configured_flag", true)
            .commit()

        val manager = SecurityLockManager(
            context = context,
            clock = FakeClock(),
            cipher = FakeSecretCipher(),
            cryptoDispatcher = UnconfinedTestDispatcher(),
            ioDispatcher = UnconfinedTestDispatcher()
        )

        assertTrue(manager.verifyPin("000999") is SecurityLockManager.VerifyResult.WrongPin)
        assertEquals(SecurityLockManager.VerifyResult.Success, manager.verifyPin("482715"))
    }

    @Test
    fun onBiometricVerified_resetsFailedAttempts_andRejectsDuringLockoutOrDisabled() = runTest {
        val (manager, clock, _) = createEnv()
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013"))

        // 未启用生物识别时拒绝
        assertFalse(manager.onBiometricVerified())

        manager.setBiometricEnabled(true)
        manager.verifyPin("999001")
        manager.verifyPin("999002")
        assertEquals(3, manager.getRemainingAttempts())

        // 冷却前生物识别通过 -> 重置失败次数为满额 5 次
        assertTrue(manager.onBiometricVerified())
        assertEquals(5, manager.getRemainingAttempts())

        // 连续错 3 次进入冷却期后，生物识别校验必须被拒绝
        manager.verifyPin("999001")
        manager.verifyPin("999002")
        assertTrue(manager.verifyPin("999003") is SecurityLockManager.VerifyResult.LockedOut)
        assertFalse(manager.onBiometricVerified())

        // 冷却结束后可再次成功并归零计数
        clock.elapsed += 30_000L
        assertTrue(manager.onBiometricVerified())
        assertEquals(5, manager.getRemainingAttempts())
    }

    @Test
    fun onBeforeDestructListener_firesBeforeCipherDestroy() = runTest {
        val tempDir = Files.createTempDirectory("f2a-order-test").toFile()
        tempDir.deleteOnExit()
        val context = FakeContext(tempDir)
        val events = ArrayList<String>()
        val cipher = object : SecretCipher {
            override fun encrypt(plainText: String) = SecretCipher.EncryptResult.Ok(plainText)
            override fun decrypt(cipherTextBase64: String) = SecretCipher.DecryptResult.Ok(cipherTextBase64)
            override fun destroyMasterKey() {
                events.add("destroyMasterKey")
            }
        }
        val manager = SecurityLockManager(
            context = context,
            clock = FakeClock(),
            cipher = cipher,
            cryptoDispatcher = UnconfinedTestDispatcher(),
            ioDispatcher = UnconfinedTestDispatcher()
        )
        manager.setOnBeforeDestructListener {
            events.add("beforeDestruct")
        }
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013", "741852"))

        assertEquals(SecurityLockManager.VerifyResult.DuressTriggered, manager.verifyPin("741852"))
        assertEquals(listOf("beforeDestruct", "destroyMasterKey"), events)
    }

    @Test
    fun concurrentVerifyPin_doesNotLoseFailedAttempts() = runBlocking {
        val tempDir = Files.createTempDirectory("f2a-concurrent-pin").toFile()
        tempDir.deleteOnExit()
        val context = FakeContext(tempDir)
        val manager = SecurityLockManager(
            context = context,
            clock = FakeClock(),
            cipher = FakeSecretCipher(),
            cryptoDispatcher = Dispatchers.Default,
            ioDispatcher = Dispatchers.Default
        )
        manager.setMaxAttempts(10)
        assertEquals(PinConfigResult.Ok, manager.setupPin("258013"))

        // 4 个并发错误尝试：第 1、2 次返回 WrongPin，第 3 次触发 30s 冷却锁，第 4 次命中 LockedOut 不再累加
        val results = (1..4).map { idx ->
            async(Dispatchers.Default) { manager.verifyPin("99900$idx") }
        }.awaitAll()

        assertEquals(4, results.size)
        assertEquals(2, results.count { it is SecurityLockManager.VerifyResult.WrongPin })
        assertEquals(2, results.count { it is SecurityLockManager.VerifyResult.LockedOut })
        assertEquals(7, manager.getRemainingAttempts())
    }
}
