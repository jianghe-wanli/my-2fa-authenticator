package com.f2a.authenticator.security

import android.content.Context
import android.content.SharedPreferences
import com.f2a.authenticator.crypto.KeyStoreManager
import com.f2a.authenticator.crypto.SecretCipher
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

sealed class PinConfigResult {
    object Ok : PinConfigResult()
    object InvalidFormat : PinConfigResult()       // 非 6 位纯数字
    object WeakPin : PinConfigResult()             // 弱密码（全同/连续/重复模式）
    object SameAsCounterpart : PinConfigResult()   // 胁迫码与主密码相同
    data class AuthFailed(val verifyResult: SecurityLockManager.VerifyResult) : PinConfigResult()
}

/**
 * 终极安全自毁防线管理器（V3 安全加固）：
 * 1. 全鉴权与写配置路径加 Mutex 互斥锁，并在 IO 线程同步 `.commit()` 防强杀重置计数；
 * 2. 独立主安全密码与胁迫密码（新哈希升级至 PBKDF2WithHmacSHA256 210K 带 `v2:` 前缀，完全兼容旧 100K 哈希）；
 * 3. 基于 Clock.elapsedRealtimeMs() 单调时钟防篡改冷却，支持设备重启后延续剩余冷却时长；
 * 4. 支持 `onBeforeDestructListener` 在毁 Key 删盘前阻断内存回写，以及 `onBiometricVerified()` 归零失败计数；
 * 5. 补齐常见弱 PIN 模式检测（AAABBB / AABBCC / ABABAB / ABCABC 等）。
 */
class SecurityLockManager(
    private val context: Context,
    private val clock: Clock = SystemClockImpl,
    private val cipher: SecretCipher = KeyStoreManager,
    private val cryptoDispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {

    private val appContext: Context = context.applicationContext ?: context
    private val prefs: SharedPreferences
        get() = appContext.getSharedPreferences(PREF_SECURITY, Context.MODE_PRIVATE)

    private val authMutex = Mutex()

    @Volatile
    private var onBeforeDestructListener: (() -> Unit)? = null

    companion object {
        private const val PREF_SECURITY = "security_vault_guard"
        private const val KEY_PIN_HASH = "vault_master_pin_hash"
        private const val KEY_PIN_SALT = "vault_master_pin_salt"
        private const val KEY_PIN_CONFIGURED_FLAG = "vault_pin_configured_flag"
        private const val KEY_DURESS_PIN_HASH = "vault_duress_pin_hash"
        private const val KEY_DURESS_PIN_SALT = "vault_duress_pin_salt"
        private const val KEY_FAILED_ATTEMPTS = "vault_failed_attempts"
        private const val KEY_LOCKOUT_UNTIL_ELAPSED = "vault_lockout_until_elapsed"
        private const val KEY_LOCKOUT_LAST_ELAPSED = "vault_lockout_last_elapsed"
        private const val KEY_LOCKOUT_REMAINING_MS = "vault_lockout_remaining_ms"

        private const val KEY_MAX_ATTEMPTS = "config_max_attempts"
        private const val KEY_FLAG_SECURE_ENABLED = "config_flag_secure_enabled"
        private const val KEY_CLIPBOARD_CLEAR_SECONDS = "config_clipboard_clear_seconds"
        private const val KEY_BIOMETRIC_ENABLED = "config_biometric_enabled"

        const val DEFAULT_MAX_ATTEMPTS = 5
        const val MIN_MAX_ATTEMPTS = 3
        const val MAX_MAX_ATTEMPTS = 10
        private const val PIN_LENGTH = 6
        private const val LEGACY_ITERATIONS = 100_000
        private const val ITERATIONS_V2 = 210_000
        private const val MIN_SUPPORTED_ITERATIONS = 10_000
        private const val MAX_SUPPORTED_ITERATIONS = 1_000_000
        private const val HASH_PREFIX_V2 = "v2:"
        private const val KEY_LENGTH = 256

        private val TRIVIAL_WEAK_PINS = setOf(
            "000001", "100000", "012345", "543210", "123450",
            "135790", "024680", "258000", "520520", "131420",
            "666888", "888666", "114514"
        )
    }

    fun setOnBeforeDestructListener(listener: (() -> Unit)?) {
        onBeforeDestructListener = listener
    }

    fun isPinConfigured(): Boolean {
        return !prefs.getString(KEY_PIN_HASH, null).isNullOrEmpty() &&
            !prefs.getString(KEY_PIN_SALT, null).isNullOrEmpty()
    }

    fun hasDuressPin(): Boolean {
        return !prefs.getString(KEY_DURESS_PIN_HASH, null).isNullOrEmpty() &&
            !prefs.getString(KEY_DURESS_PIN_SALT, null).isNullOrEmpty()
    }

    /**
     * 检测降级攻击异常：例如攻击者清空 security_vault_guard.xml 或删除主 PIN 哈希，
     * 但磁盘上仍存有加密令牌，或曾标记过已配置 PIN 却丢失哈希。
     */
    fun isPinMissingAnomaly(hasStoredEncryptedTokens: Boolean = false): Boolean {
        if (isPinConfigured()) return false
        return hasStoredEncryptedTokens || prefs.getBoolean(KEY_PIN_CONFIGURED_FLAG, false)
    }

    fun getMaxAttempts(): Int {
        return prefs.getInt(KEY_MAX_ATTEMPTS, DEFAULT_MAX_ATTEMPTS)
            .coerceIn(MIN_MAX_ATTEMPTS, MAX_MAX_ATTEMPTS)
    }

    fun setMaxAttempts(maxAttempts: Int) {
        prefs.edit().putInt(KEY_MAX_ATTEMPTS, maxAttempts.coerceIn(MIN_MAX_ATTEMPTS, MAX_MAX_ATTEMPTS)).commit()
    }

    fun isFlagSecureEnabled(): Boolean {
        return prefs.getBoolean(KEY_FLAG_SECURE_ENABLED, true)
    }

    fun setFlagSecureEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_FLAG_SECURE_ENABLED, enabled).commit()
    }

    fun getClipboardClearSeconds(): Int {
        return prefs.getInt(KEY_CLIPBOARD_CLEAR_SECONDS, 45).coerceAtLeast(0)
    }

    fun setClipboardClearSeconds(seconds: Int) {
        prefs.edit().putInt(KEY_CLIPBOARD_CLEAR_SECONDS, seconds.coerceAtLeast(0)).commit()
    }

    fun isBiometricEnabled(): Boolean {
        return prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false)
    }

    fun setBiometricEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, enabled).commit()
    }

    fun getRemainingAttempts(): Int {
        val max = getMaxAttempts()
        val failed = prefs.getInt(KEY_FAILED_ATTEMPTS, 0)
        return (max - failed).coerceAtLeast(0)
    }

    /**
     * 基于单调时钟计算剩余锁定秒数，且在设备重启（elapsedRealtime 回绕清零）后延续上次剩余冷却时长。
     */
    fun getLockoutRemainingSeconds(): Long {
        val remainingMs = getLockoutRemainingMs()
        if (remainingMs <= 0L) return 0L
        return (remainingMs + 999L) / 1000L
    }

    private fun getLockoutRemainingMs(): Long {
        val remainingStored = prefs.getLong(KEY_LOCKOUT_REMAINING_MS, 0L)
        val untilElapsed = prefs.getLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
        val lastElapsed = prefs.getLong(KEY_LOCKOUT_LAST_ELAPSED, 0L)
        if (remainingStored <= 0L && untilElapsed <= 0L) return 0L

        val nowElapsed = clock.elapsedRealtimeMs()
        return if (nowElapsed < lastElapsed) {
            // 检测到设备重启（单调时钟小于上次记录值），按上次剩余冷却时长重新锚定到期时刻
            val newUntil = nowElapsed + remainingStored
            prefs.edit()
                .putLong(KEY_LOCKOUT_LAST_ELAPSED, nowElapsed)
                .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, newUntil)
                .commit()
            remainingStored
        } else {
            val diff = untilElapsed - nowElapsed
            if (diff <= 0L) {
                clearLockoutStateLocked()
                0L
            } else {
                prefs.edit()
                    .putLong(KEY_LOCKOUT_LAST_ELAPSED, nowElapsed)
                    .putLong(KEY_LOCKOUT_REMAINING_MS, diff)
                    .commit()
                diff
            }
        }
    }

    private fun saveLockoutStateLocked(delayMs: Long) {
        val nowElapsed = clock.elapsedRealtimeMs()
        prefs.edit()
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, nowElapsed + delayMs)
            .putLong(KEY_LOCKOUT_LAST_ELAPSED, nowElapsed)
            .putLong(KEY_LOCKOUT_REMAINING_MS, delayMs)
            .commit()
    }

    private fun clearLockoutStateLocked() {
        prefs.edit()
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_LAST_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_REMAINING_MS, 0L)
            .commit()
    }

    private fun resetAttemptsAndLockoutLocked() {
        prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_LAST_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_REMAINING_MS, 0L)
            .commit()
    }

    private fun validatePinFormatAndStrength(pin: String): PinConfigResult? {
        if (pin.length != PIN_LENGTH || !pin.all { it in '0'..'9' }) {
            return PinConfigResult.InvalidFormat
        }
        // 1. 全同数字 (如 111111)
        if (pin.all { it == pin[0] }) {
            return PinConfigResult.WeakPin
        }
        // 2. 连续顺逆序 (如 123456, 654321)
        val diffs = (0 until pin.length - 1).map { pin[it + 1] - pin[it] }
        if (diffs.all { it == 1 } || diffs.all { it == -1 }) {
            return PinConfigResult.WeakPin
        }
        // 3. AAABBB (如 111222)
        if (pin[0] == pin[1] && pin[1] == pin[2] && pin[3] == pin[4] && pin[4] == pin[5]) {
            return PinConfigResult.WeakPin
        }
        // 4. AABBCC (如 112233)
        if (pin[0] == pin[1] && pin[2] == pin[3] && pin[4] == pin[5]) {
            return PinConfigResult.WeakPin
        }
        // 5. ABABAB (如 121212)
        if (pin[0] == pin[2] && pin[2] == pin[4] && pin[1] == pin[3] && pin[3] == pin[5]) {
            return PinConfigResult.WeakPin
        }
        // 6. ABCABC (如 123123)
        if (pin.substring(0, 3) == pin.substring(3, 6)) {
            return PinConfigResult.WeakPin
        }
        // 7. 镜像顺序列 ABCCBA (如 123321, 654456)
        if (pin.substring(0, 3) == pin.substring(3, 6).reversed() &&
            kotlin.math.abs(pin[1] - pin[0]) == 1 &&
            pin[2] - pin[1] == pin[1] - pin[0]
        ) {
            return PinConfigResult.WeakPin
        }
        // 8. 常见极弱数字组合
        if (pin in TRIVIAL_WEAK_PINS) {
            return PinConfigResult.WeakPin
        }
        return null
    }

    suspend fun setupPin(masterPin: String, duressPin: String? = null): PinConfigResult {
        validatePinFormatAndStrength(masterPin)?.let { return it }
        if (duressPin != null) {
            validatePinFormatAndStrength(duressPin)?.let { return it }
            if (duressPin == masterPin) return PinConfigResult.SameAsCounterpart
        }

        return authMutex.withLock {
            val (masterSalt, masterHash, duressPair) = withContext(cryptoDispatcher) {
                val mSalt = generateSalt()
                val mHash = hashPinV2(masterPin, mSalt)
                val dPair = if (duressPin != null) {
                    val dSalt = generateSalt()
                    val dHash = hashPinV2(duressPin, dSalt)
                    dSalt to dHash
                } else {
                    null
                }
                Triple(mSalt, mHash, dPair)
            }

            withContext(ioDispatcher) {
                val editor = prefs.edit()
                    .putString(KEY_PIN_HASH, masterHash)
                    .putString(KEY_PIN_SALT, Base64.getEncoder().encodeToString(masterSalt))
                    .putBoolean(KEY_PIN_CONFIGURED_FLAG, true)
                    .putInt(KEY_FAILED_ATTEMPTS, 0)
                    .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
                    .putLong(KEY_LOCKOUT_LAST_ELAPSED, 0L)
                    .putLong(KEY_LOCKOUT_REMAINING_MS, 0L)

                if (duressPair != null) {
                    editor
                        .putString(KEY_DURESS_PIN_SALT, Base64.getEncoder().encodeToString(duressPair.first))
                        .putString(KEY_DURESS_PIN_HASH, duressPair.second)
                } else {
                    editor
                        .remove(KEY_DURESS_PIN_HASH)
                        .remove(KEY_DURESS_PIN_SALT)
                }
                editor.commit()
            }
            PinConfigResult.Ok
        }
    }

    suspend fun changeMasterPin(currentPin: String, newPin: String): PinConfigResult {
        validatePinFormatAndStrength(newPin)?.let { return it }

        return authMutex.withLock {
            val authResult = verifyPinLocked(currentPin)
            if (authResult != VerifyResult.Success) {
                return@withLock PinConfigResult.AuthFailed(authResult)
            }

            val duressHash = prefs.getString(KEY_DURESS_PIN_HASH, null)
            val duressSaltStr = prefs.getString(KEY_DURESS_PIN_SALT, null)
            if (!duressHash.isNullOrEmpty() && !duressSaltStr.isNullOrEmpty()) {
                val matchesDuress = withContext(cryptoDispatcher) {
                    val duressSalt = decodeBase64OrNull(duressSaltStr) ?: return@withContext false
                    verifyHash(newPin, duressSalt, duressHash)
                }
                if (matchesDuress) {
                    return@withLock PinConfigResult.SameAsCounterpart
                }
            }

            val (newSalt, newHash) = withContext(cryptoDispatcher) {
                val salt = generateSalt()
                salt to hashPinV2(newPin, salt)
            }

            withContext(ioDispatcher) {
                prefs.edit()
                    .putString(KEY_PIN_HASH, newHash)
                    .putString(KEY_PIN_SALT, Base64.getEncoder().encodeToString(newSalt))
                    .putBoolean(KEY_PIN_CONFIGURED_FLAG, true)
                    .putInt(KEY_FAILED_ATTEMPTS, 0)
                    .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
                    .putLong(KEY_LOCKOUT_LAST_ELAPSED, 0L)
                    .putLong(KEY_LOCKOUT_REMAINING_MS, 0L)
                    .commit()
            }
            PinConfigResult.Ok
        }
    }

    suspend fun setDuressPin(currentMasterPin: String, duressPin: String): PinConfigResult {
        validatePinFormatAndStrength(duressPin)?.let { return it }

        return authMutex.withLock {
            val authResult = verifyPinLocked(currentMasterPin)
            if (authResult != VerifyResult.Success) {
                return@withLock PinConfigResult.AuthFailed(authResult)
            }

            if (duressPin == currentMasterPin) {
                return@withLock PinConfigResult.SameAsCounterpart
            }

            val (duressSalt, duressHash) = withContext(cryptoDispatcher) {
                val salt = generateSalt()
                salt to hashPinV2(duressPin, salt)
            }

            withContext(ioDispatcher) {
                prefs.edit()
                    .putString(KEY_DURESS_PIN_HASH, duressHash)
                    .putString(KEY_DURESS_PIN_SALT, Base64.getEncoder().encodeToString(duressSalt))
                    .commit()
            }
            PinConfigResult.Ok
        }
    }

    suspend fun clearDuressPin(currentMasterPin: String): PinConfigResult {
        return authMutex.withLock {
            val authResult = verifyPinLocked(currentMasterPin)
            if (authResult != VerifyResult.Success) {
                return@withLock PinConfigResult.AuthFailed(authResult)
            }

            withContext(ioDispatcher) {
                prefs.edit()
                    .remove(KEY_DURESS_PIN_HASH)
                    .remove(KEY_DURESS_PIN_SALT)
                    .commit()
            }
            PinConfigResult.Ok
        }
    }

    /**
     * 生物识别通过后的状态对齐：冷却期内或未开启生物识别/未设 PIN 返回 false；
     * 否则在互斥锁下同步清零失败次数与冷却记录，防止后续单次 PIN 误输直接触发自毁。
     */
    suspend fun onBiometricVerified(): Boolean {
        return authMutex.withLock {
            if (!isPinConfigured() || !isBiometricEnabled()) {
                return@withLock false
            }
            if (getLockoutRemainingSeconds() > 0L) {
                return@withLock false
            }
            withContext(ioDispatcher) {
                resetAttemptsAndLockoutLocked()
            }
            true
        }
    }

    suspend fun verifyPin(inputPin: String): VerifyResult {
        return authMutex.withLock {
            verifyPinLocked(inputPin)
        }
    }

    private suspend fun verifyPinLocked(inputPin: String): VerifyResult {
        val lockoutSec = withContext(ioDispatcher) { getLockoutRemainingSeconds() }
        if (lockoutSec > 0L) {
            return VerifyResult.LockedOut(lockoutSec)
        }

        // 1. 先检查是否匹配胁迫密码（常量时间比较）
        val duressHash = prefs.getString(KEY_DURESS_PIN_HASH, null)
        val duressSaltStr = prefs.getString(KEY_DURESS_PIN_SALT, null)
        if (!duressHash.isNullOrEmpty() && !duressSaltStr.isNullOrEmpty()) {
            val matchedDuress = withContext(cryptoDispatcher) {
                val salt = decodeBase64OrNull(duressSaltStr) ?: return@withContext false
                verifyHash(inputPin, salt, duressHash)
            }
            if (matchedDuress) {
                executePermanentSelfDestructLocked(silent = true)
                return VerifyResult.DuressTriggered
            }
        }

        // 2. 检查主密码（未配置时返回 NotConfigured，绝不 fail-open）
        val savedHash = prefs.getString(KEY_PIN_HASH, null)
        val saltStr = prefs.getString(KEY_PIN_SALT, null)
        if (savedHash.isNullOrEmpty() || saltStr.isNullOrEmpty()) {
            return VerifyResult.NotConfigured
        }

        val matchedMaster = withContext(cryptoDispatcher) {
            val salt = decodeBase64OrNull(saltStr) ?: return@withContext false
            verifyHash(inputPin, salt, savedHash)
        }

        if (matchedMaster) {
            withContext(ioDispatcher) {
                resetAttemptsAndLockoutLocked()
            }
            return VerifyResult.Success
        }

        val max = getMaxAttempts()
        val failed = prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1
        withContext(ioDispatcher) {
            prefs.edit().putInt(KEY_FAILED_ATTEMPTS, failed).commit()
        }

        if (failed >= max) {
            executePermanentSelfDestructLocked(silent = false)
            return VerifyResult.SelfDestructed
        }

        if (failed >= 3) {
            val delaySeconds = 30L * (failed - 2)
            withContext(ioDispatcher) {
                saveLockoutStateLocked(delaySeconds * 1000L)
            }
            return VerifyResult.LockedOut(delaySeconds)
        }

        return VerifyResult.WrongPin(remaining = (max - failed).coerceAtLeast(0))
    }

    /**
     * 销毁硬件密钥与本地数据目录。
     * 先触发 onBeforeDestructListener 同步阻断内存库/偏好/剪贴板，再执行删 Key 与删盘。
     */
    suspend fun executePermanentSelfDestruct(silent: Boolean = false) {
        authMutex.withLock {
            executePermanentSelfDestructLocked(silent)
        }
    }

    private suspend fun executePermanentSelfDestructLocked(@Suppress("UNUSED_PARAMETER") silent: Boolean) {
        try {
            onBeforeDestructListener?.invoke()
        } catch (_: Exception) {
        }

        try {
            cipher.destroyMasterKey()
        } catch (_: Exception) {
        }

        withContext(ioDispatcher) {
            try {
                val deleted = appContext.deleteSharedPreferences(PREF_SECURITY)
                if (!deleted) {
                    prefs.edit().clear().commit()
                }
            } catch (_: Exception) {
                try {
                    prefs.edit().clear().commit()
                } catch (_: Exception) {
                }
            }
            try {
                appContext.deleteSharedPreferences("my_2fa_secure_store")
                appContext.deleteSharedPreferences("my_2fa_vault_prefs")
            } catch (_: Exception) {
            }

            try {
                val dataDirPath = appContext.applicationInfo?.dataDir
                if (!dataDirPath.isNullOrBlank()) {
                    val dataDir = File(dataDirPath)
                    File(dataDir, "files").deleteRecursively()
                    File(dataDir, "shared_prefs").deleteRecursively()
                    File(dataDir, "cache").deleteRecursively()
                    File(dataDir, "code_cache").deleteRecursively()
                }
            } catch (_: Exception) {
            }
        }
    }

    private fun decodeBase64OrNull(encoded: String): ByteArray? = try {
        Base64.getDecoder().decode(encoded)
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun generateSalt(): ByteArray {
        val salt = ByteArray(32)
        SecureRandom().nextBytes(salt)
        return salt
    }

    private fun hashPinV2(pin: String, salt: ByteArray): String {
        val encoded = hashPinRaw(pin, salt, ITERATIONS_V2)
        return "$HASH_PREFIX_V2$ITERATIONS_V2:$encoded"
    }

    private fun verifyHash(pin: String, salt: ByteArray, storedHash: String): Boolean {
        return if (storedHash.startsWith(HASH_PREFIX_V2)) {
            val rest = storedHash.removePrefix(HASH_PREFIX_V2)
            val colonIdx = rest.indexOf(':')
            if (colonIdx <= 0) return false
            val iter = rest.substring(0, colonIdx).toIntOrNull() ?: return false
            if (iter !in MIN_SUPPORTED_ITERATIONS..MAX_SUPPORTED_ITERATIONS) return false
            val expectedB64 = rest.substring(colonIdx + 1)
            if (expectedB64.isEmpty()) return false
            constEq(hashPinRaw(pin, salt, iter), expectedB64)
        } else {
            constEq(hashPinRaw(pin, salt, LEGACY_ITERATIONS), storedHash)
        }
    }

    private fun hashPinRaw(pin: String, salt: ByteArray, iterations: Int): String {
        val chars = pin.toCharArray()
        val spec = PBEKeySpec(chars, salt, iterations, KEY_LENGTH)
        var hash: ByteArray? = null
        return try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            hash = factory.generateSecret(spec).encoded
            Base64.getEncoder().encodeToString(hash)
        } finally {
            spec.clearPassword()
            chars.fill('\u0000')
            hash?.fill(0)
        }
    }

    /** 常量时间比较，避免短路时序侧信道 */
    private fun constEq(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

    sealed class VerifyResult {
        object Success : VerifyResult()
        object NotConfigured : VerifyResult()
        object DuressTriggered : VerifyResult()
        object SelfDestructed : VerifyResult()
        data class WrongPin(val remaining: Int) : VerifyResult()
        data class LockedOut(val waitSeconds: Long) : VerifyResult()
    }
}
