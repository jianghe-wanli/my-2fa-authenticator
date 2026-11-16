package com.f2a.authenticator.security

import android.content.Context
import android.content.SharedPreferences
import com.f2a.authenticator.crypto.KeyStoreManager
import com.f2a.authenticator.crypto.SecretCipher
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
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
    object WeakPin : PinConfigResult()             // 全同数字或连续顺逆序
    object SameAsCounterpart : PinConfigResult()   // 胁迫码与主密码相同
    data class AuthFailed(val verifyResult: SecurityLockManager.VerifyResult) : PinConfigResult()
}

/**
 * 终极安全自毁防线管理器（V2 重构）：
 * 1. 独立主安全密码与胁迫密码（PBKDF2WithHmacSHA256 100K 迭代，Dispatchers.Default 异步执行，擦除 PBEKeySpec）
 * 2. 基于 Clock.elapsedRealtimeMs() 单调时钟防篡改冷却，且支持设备重启后延续剩余冷却时长
 * 3. 主密码修改、胁迫码设置与清除（强制 6 位数字、拦截弱 PIN、严禁主密与胁迫码同密）
 * 4. 缺失 PIN 降级异常检测与非阻塞自毁（不再在库层擅自 exitProcess(0)）
 */
class SecurityLockManager(
    private val context: Context,
    private val clock: Clock = SystemClockImpl,
    private val cipher: SecretCipher = KeyStoreManager,
    private val cryptoDispatcher: CoroutineDispatcher = Dispatchers.Default
) {

    private val appContext: Context = context.applicationContext ?: context
    private val prefs: SharedPreferences
        get() = appContext.getSharedPreferences(PREF_SECURITY, Context.MODE_PRIVATE)

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
        private const val ITERATIONS = 100_000
        private const val KEY_LENGTH = 256
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
        prefs.edit().putInt(KEY_MAX_ATTEMPTS, maxAttempts.coerceIn(MIN_MAX_ATTEMPTS, MAX_MAX_ATTEMPTS)).apply()
    }

    fun isFlagSecureEnabled(): Boolean {
        return prefs.getBoolean(KEY_FLAG_SECURE_ENABLED, true)
    }

    fun setFlagSecureEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_FLAG_SECURE_ENABLED, enabled).apply()
    }

    fun getClipboardClearSeconds(): Int {
        return prefs.getInt(KEY_CLIPBOARD_CLEAR_SECONDS, 45).coerceAtLeast(0)
    }

    fun setClipboardClearSeconds(seconds: Int) {
        prefs.edit().putInt(KEY_CLIPBOARD_CLEAR_SECONDS, seconds.coerceAtLeast(0)).apply()
    }

    fun isBiometricEnabled(): Boolean {
        return prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false)
    }

    fun setBiometricEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, enabled).apply()
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
                .apply()
            remainingStored
        } else {
            val diff = untilElapsed - nowElapsed
            if (diff <= 0L) {
                clearLockoutState()
                0L
            } else {
                prefs.edit()
                    .putLong(KEY_LOCKOUT_LAST_ELAPSED, nowElapsed)
                    .putLong(KEY_LOCKOUT_REMAINING_MS, diff)
                    .apply()
                diff
            }
        }
    }

    private fun saveLockoutState(delayMs: Long) {
        val nowElapsed = clock.elapsedRealtimeMs()
        prefs.edit()
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, nowElapsed + delayMs)
            .putLong(KEY_LOCKOUT_LAST_ELAPSED, nowElapsed)
            .putLong(KEY_LOCKOUT_REMAINING_MS, delayMs)
            .apply()
    }

    private fun clearLockoutState() {
        prefs.edit()
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_LAST_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_REMAINING_MS, 0L)
            .apply()
    }

    private fun validatePinFormatAndStrength(pin: String): PinConfigResult? {
        if (pin.length != PIN_LENGTH || !pin.all { it in '0'..'9' }) {
            return PinConfigResult.InvalidFormat
        }
        if (pin.all { it == pin[0] }) {
            return PinConfigResult.WeakPin
        }
        val diffs = (0 until pin.length - 1).map { pin[it + 1] - pin[it] }
        if (diffs.all { it == 1 } || diffs.all { it == -1 }) {
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

        val (masterSalt, masterHash, duressPair) = withContext(cryptoDispatcher) {
            val mSalt = generateSalt()
            val mHash = hashPin(masterPin, mSalt)
            val dPair = if (duressPin != null) {
                val dSalt = generateSalt()
                val dHash = hashPin(duressPin, dSalt)
                dSalt to dHash
            } else {
                null
            }
            Triple(mSalt, mHash, dPair)
        }

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

        editor.apply()
        return PinConfigResult.Ok
    }

    suspend fun changeMasterPin(currentPin: String, newPin: String): PinConfigResult {
        validatePinFormatAndStrength(newPin)?.let { return it }

        val authResult = verifyPin(currentPin)
        if (authResult != VerifyResult.Success) {
            return PinConfigResult.AuthFailed(authResult)
        }

        val duressHash = prefs.getString(KEY_DURESS_PIN_HASH, null)
        val duressSaltStr = prefs.getString(KEY_DURESS_PIN_SALT, null)
        if (!duressHash.isNullOrEmpty() && !duressSaltStr.isNullOrEmpty()) {
            val matchesDuress = withContext(cryptoDispatcher) {
                val duressSalt = decodeBase64OrNull(duressSaltStr) ?: return@withContext false
                constEq(hashPin(newPin, duressSalt), duressHash)
            }
            if (matchesDuress) {
                return PinConfigResult.SameAsCounterpart
            }
        }

        val (newSalt, newHash) = withContext(cryptoDispatcher) {
            val salt = generateSalt()
            salt to hashPin(newPin, salt)
        }

        prefs.edit()
            .putString(KEY_PIN_HASH, newHash)
            .putString(KEY_PIN_SALT, Base64.getEncoder().encodeToString(newSalt))
            .putBoolean(KEY_PIN_CONFIGURED_FLAG, true)
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_LAST_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_REMAINING_MS, 0L)
            .apply()

        return PinConfigResult.Ok
    }

    suspend fun setDuressPin(currentMasterPin: String, duressPin: String): PinConfigResult {
        validatePinFormatAndStrength(duressPin)?.let { return it }

        val authResult = verifyPin(currentMasterPin)
        if (authResult != VerifyResult.Success) {
            return PinConfigResult.AuthFailed(authResult)
        }

        if (duressPin == currentMasterPin) {
            return PinConfigResult.SameAsCounterpart
        }

        val (duressSalt, duressHash) = withContext(cryptoDispatcher) {
            val salt = generateSalt()
            salt to hashPin(duressPin, salt)
        }

        prefs.edit()
            .putString(KEY_DURESS_PIN_HASH, duressHash)
            .putString(KEY_DURESS_PIN_SALT, Base64.getEncoder().encodeToString(duressSalt))
            .apply()

        return PinConfigResult.Ok
    }

    suspend fun clearDuressPin(currentMasterPin: String): PinConfigResult {
        val authResult = verifyPin(currentMasterPin)
        if (authResult != VerifyResult.Success) {
            return PinConfigResult.AuthFailed(authResult)
        }

        prefs.edit()
            .remove(KEY_DURESS_PIN_HASH)
            .remove(KEY_DURESS_PIN_SALT)
            .apply()

        return PinConfigResult.Ok
    }

    suspend fun verifyPin(inputPin: String): VerifyResult {
        val lockoutSec = getLockoutRemainingSeconds()
        if (lockoutSec > 0L) {
            return VerifyResult.LockedOut(lockoutSec)
        }

        // 1. 先检查是否匹配胁迫密码（常量时间比较）
        val duressHash = prefs.getString(KEY_DURESS_PIN_HASH, null)
        val duressSaltStr = prefs.getString(KEY_DURESS_PIN_SALT, null)
        if (!duressHash.isNullOrEmpty() && !duressSaltStr.isNullOrEmpty()) {
            val matchedDuress = withContext(cryptoDispatcher) {
                val salt = decodeBase64OrNull(duressSaltStr) ?: return@withContext false
                constEq(hashPin(inputPin, salt), duressHash)
            }
            if (matchedDuress) {
                executePermanentSelfDestruct(silent = true)
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
            constEq(hashPin(inputPin, salt), savedHash)
        }

        if (matchedMaster) {
            prefs.edit()
                .putInt(KEY_FAILED_ATTEMPTS, 0)
                .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
                .putLong(KEY_LOCKOUT_LAST_ELAPSED, 0L)
                .putLong(KEY_LOCKOUT_REMAINING_MS, 0L)
                .apply()
            return VerifyResult.Success
        }

        val max = getMaxAttempts()
        val failed = prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1
        prefs.edit().putInt(KEY_FAILED_ATTEMPTS, failed).apply()

        if (failed >= max) {
            executePermanentSelfDestruct(silent = false)
            return VerifyResult.SelfDestructed
        }

        if (failed >= 3) {
            val delaySeconds = 30L * (failed - 2)
            saveLockoutState(delaySeconds * 1000L)
            return VerifyResult.LockedOut(delaySeconds)
        }

        return VerifyResult.WrongPin(remaining = (max - failed).coerceAtLeast(0))
    }

    /**
     * 销毁硬件密钥与本地数据目录。
     * 不再在底层库擅自调用 exitProcess(0)；非静默主动引爆由上层 Activity.finishAndRemoveTask() 配合完成。
     */
    suspend fun executePermanentSelfDestruct(@Suppress("UNUSED_PARAMETER") silent: Boolean = false) {
        try {
            cipher.destroyMasterKey()
        } catch (_: Exception) {
        }

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

        withContext(Dispatchers.IO) {
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

    private fun hashPin(pin: String, salt: ByteArray): String {
        val chars = pin.toCharArray()
        val spec = PBEKeySpec(chars, salt, ITERATIONS, KEY_LENGTH)
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
