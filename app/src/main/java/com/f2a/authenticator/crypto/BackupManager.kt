package com.f2a.authenticator.crypto

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.BackupPayload
import com.f2a.authenticator.data.model.CURRENT_VAULT_SCHEMA_VERSION
import com.f2a.authenticator.totp.OtpEngine
import com.google.gson.Gson
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

enum class BackupError {
    INVALID_BASE64,
    CORRUPT_FORMAT,
    UNSUPPORTED_VERSION,
    INVALID_ITERATIONS,
    WRONG_PASSPHRASE_OR_TAMPERED,
    EMPTY_PAYLOAD,
    ENCRYPTION_FAILED
}

sealed class BackupExportResult {
    data class Ok(
        val encodedBase64: String,
        val exportedCount: Int,
        val skippedInvalidCount: Int
    ) : BackupExportResult()

    data class Error(val error: BackupError, val message: String) : BackupExportResult()
}

sealed class BackupImportResult {
    data class Ok(
        val payload: BackupPayload,
        val skippedCorruptTokens: Int
    ) : BackupImportResult()

    data class Error(val error: BackupError, val message: String) : BackupImportResult()
}

/**
 * 端到端零知识加密备份导出/导入引擎（纯 Kotlin，支持 JVM 单元测试）。
 *
 * - JDF2 v2 格式：magic("JDF2") | version(1B=2) | iterations(4B BE=210_000) | salt(16B) | iv(12B) | ciphertext+GCM_TAG(16B)
 * - 严格保持与既有 JDF2 密文的 100% 兼容性（不额外注入 updateAAD）
 * - 保留 legacy v1（无 magic、裸 SHA-256）读取路径；若输入带 "JDF2" 前缀，绝不回退 legacy
 */
object BackupManager {

    const val MIN_RECOMMENDED_PASSPHRASE_LENGTH = 8
    const val MAX_BACKUP_RAW_BYTES = 10 * 1024 * 1024
    private const val MAX_BACKUP_BASE64_LENGTH = 15 * 1024 * 1024

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    private const val GCM_TAG_BYTES = GCM_TAG_LENGTH / 8
    private const val IV_LENGTH = 12
    private const val SALT_LENGTH = 16
    private const val ITERATIONS = 210_000
    private const val MIN_ITERATIONS = 10_000
    private const val MAX_ITERATIONS = 1_000_000
    private const val KEY_BITS = 256
    private const val MAGIC = "JDF2"
    private const val VERSION: Byte = 2
    private const val HEADER_LENGTH_V2 = 4 + 1 + 4 + SALT_LENGTH + IV_LENGTH
    private const val MIN_BYTES_V2 = HEADER_LENGTH_V2 + GCM_TAG_BYTES
    private const val MIN_BYTES_LEGACY = IV_LENGTH + GCM_TAG_BYTES
    private const val BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    private val MAGIC_BYTES = MAGIC.toByteArray(StandardCharsets.US_ASCII)
    private val gson = Gson()

    /**
     * 评估备份口令强度等级：0 = 过短(<8)或纯空白，1 = 弱，2 = 中，3 = 强。
     */
    fun evaluatePassphraseStrength(passphrase: String): Int {
        if (passphrase.isBlank() || passphrase.length < MIN_RECOMMENDED_PASSPHRASE_LENGTH) {
            return 0
        }
        val hasDigit = passphrase.any { it.isDigit() }
        val hasLower = passphrase.any { it.isLowerCase() }
        val hasUpper = passphrase.any { it.isUpperCase() }
        val hasSymbol = passphrase.any { !it.isLetterOrDigit() }
        val charClasses = listOf(hasDigit, hasLower, hasUpper, hasSymbol).count { it }
        return when {
            passphrase.length >= 12 && charClasses >= 3 -> 3
            charClasses >= 2 || passphrase.length >= 12 -> 2
            else -> 1
        }
    }

    private fun deriveKey(passphrase: String, salt: ByteArray, iterations: Int): SecretKeySpec {
        val chars = passphrase.toCharArray()
        val spec = PBEKeySpec(chars, salt, iterations, KEY_BITS)
        var keyBytes: ByteArray? = null
        return try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            keyBytes = factory.generateSecret(spec).encoded
            SecretKeySpec(keyBytes, "AES")
        } finally {
            spec.clearPassword()
            chars.fill('\u0000')
            keyBytes?.fill(0)
        }
    }

    private fun isValidBase32Secret(secret: String): Boolean {
        val cleaned = secret.trim()
            .replace("-", "")
            .replace(" ", "")
            .replace("\n", "")
            .replace("\r", "")
            .replace("=", "")
            .uppercase(Locale.US)
        return cleaned.isNotEmpty() &&
            cleaned.all { it in BASE32_CHARS } &&
            OtpEngine.decodeBase32(cleaned).isNotEmpty()
    }

    private fun startsWithMagic(raw: ByteArray): Boolean {
        if (raw.size < MAGIC_BYTES.size) return false
        for (i in MAGIC_BYTES.indices) {
            if (raw[i] != MAGIC_BYTES[i]) return false
        }
        return true
    }

    /**
     * 基于用户给定的备份口令生成 AES-256-GCM 加密备份包字符串（JDF2 v2 强 KDF 格式）。
     * 自动过滤损坏令牌（secretInvalid == true）与回收站软删除令牌（deletedAt != null）。
     */
    fun exportEncryptedBackup(payload: BackupPayload, backupPassphrase: String): BackupExportResult {
        if (backupPassphrase.isBlank()) {
            return BackupExportResult.Error(BackupError.ENCRYPTION_FAILED, "备份口令不能为空")
        }

        val allTokens = payload.tokens
        val exportableTokens = allTokens.filter { !it.secretInvalid && it.deletedAt == null && it.secret.isNotBlank() }
        val skippedInvalidCount = allTokens.size - exportableTokens.size

        val sanitizedWorkspaces = payload.workspaces.map { it.normalize() }
        val sanitizedTags = payload.tags.map { it.normalize() }
        if (exportableTokens.isEmpty() && sanitizedWorkspaces.isEmpty() && sanitizedTags.isEmpty()) {
            return BackupExportResult.Error(BackupError.EMPTY_PAYLOAD, "没有可导出的有效数据")
        }

        val sanitizedPayload = payload.copy(
            version = VERSION.toInt(),
            schemaVersion = CURRENT_VAULT_SCHEMA_VERSION,
            workspaces = sanitizedWorkspaces,
            tags = sanitizedTags,
            tokens = exportableTokens.map { it.normalize() }
        )

        var plainBytes: ByteArray? = null
        return try {
            val json = gson.toJson(sanitizedPayload)
            plainBytes = json.toByteArray(StandardCharsets.UTF_8)
            val salt = ByteArray(SALT_LENGTH).also { SecureRandom().nextBytes(it) }
            val secretKey = deriveKey(backupPassphrase, salt, ITERATIONS)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val iv = cipher.iv
            val encrypted = cipher.doFinal(plainBytes)

            val out = ByteArrayOutputStream(HEADER_LENGTH_V2 + encrypted.size)
            out.write(MAGIC_BYTES)
            out.write(VERSION.toInt())
            out.write(ByteBuffer.allocate(4).putInt(ITERATIONS).array())
            out.write(salt)
            out.write(iv)
            out.write(encrypted)

            val encoded = Base64.getEncoder().encodeToString(out.toByteArray())
            BackupExportResult.Ok(
                encodedBase64 = encoded,
                exportedCount = exportableTokens.size,
                skippedInvalidCount = skippedInvalidCount
            )
        } catch (e: Exception) {
            BackupExportResult.Error(
                BackupError.ENCRYPTION_FAILED,
                e.message ?: "加密备份失败"
            )
        } finally {
            plainBytes?.fill(0)
        }
    }

    /**
     * 使用备份口令解密并解析备份包。
     * 若带有 JDF2 魔数，仅走 v2 路径且绝不回退 legacy；否则走 legacy v1 兼容读取。
     */
    fun importEncryptedBackup(encryptedBase64: String, backupPassphrase: String): BackupImportResult {
        val trimmed = encryptedBase64.trim()
        if (trimmed.isEmpty()) {
            return BackupImportResult.Error(BackupError.EMPTY_PAYLOAD, "备份内容为空")
        }
        if (trimmed.length > MAX_BACKUP_BASE64_LENGTH) {
            return BackupImportResult.Error(BackupError.CORRUPT_FORMAT, "备份数据体积超出安全上限（最大 10MB）")
        }

        val raw = try {
            Base64.getDecoder().decode(trimmed)
        } catch (_: IllegalArgumentException) {
            return BackupImportResult.Error(BackupError.INVALID_BASE64, "备份内容不是有效的 Base64 编码")
        }

        if (raw.size > MAX_BACKUP_RAW_BYTES) {
            return BackupImportResult.Error(BackupError.CORRUPT_FORMAT, "备份数据体积超出安全上限（最大 10MB）")
        }

        return if (startsWithMagic(raw)) {
            importV2(raw, backupPassphrase)
        } else {
            importLegacy(raw, backupPassphrase)
        }
    }

    private fun importV2(raw: ByteArray, passphrase: String): BackupImportResult {
        if (raw.size < MIN_BYTES_V2) {
            return BackupImportResult.Error(BackupError.CORRUPT_FORMAT, "JDF2 备份数据长度不足或已截断")
        }

        var offset = MAGIC_BYTES.size
        val version = raw[offset].toInt() and 0xFF
        offset += 1
        if (version != VERSION.toInt()) {
            return BackupImportResult.Error(BackupError.UNSUPPORTED_VERSION, "不支持的备份版本: v$version")
        }

        val iterations = ByteBuffer.wrap(raw, offset, 4).int
        offset += 4
        if (iterations !in MIN_ITERATIONS..MAX_ITERATIONS) {
            return BackupImportResult.Error(
                BackupError.INVALID_ITERATIONS,
                "KDF 迭代次数 $iterations 超出安全允许区间 ($MIN_ITERATIONS..$MAX_ITERATIONS)"
            )
        }

        val salt = raw.copyOfRange(offset, offset + SALT_LENGTH)
        offset += SALT_LENGTH
        val iv = raw.copyOfRange(offset, offset + IV_LENGTH)
        offset += IV_LENGTH
        val cipherText = raw.copyOfRange(offset, raw.size)

        var decryptedBytes: ByteArray? = null
        return try {
            val key = deriveKey(passphrase, salt, iterations)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            decryptedBytes = cipher.doFinal(cipherText)
            val decryptedJson = String(decryptedBytes, StandardCharsets.UTF_8)
            validateAndSanitize(decryptedJson)
        } catch (_: AEADBadTagException) {
            BackupImportResult.Error(BackupError.WRONG_PASSPHRASE_OR_TAMPERED, "备份口令错误或备份数据已被篡改")
        } catch (e: Exception) {
            BackupImportResult.Error(BackupError.CORRUPT_FORMAT, e.message ?: "JDF2 解密失败")
        } finally {
            decryptedBytes?.fill(0)
        }
    }

    /** 旧版格式：Base64(iv + ciphertext)，裸 SHA-256 派生（仅兼容无 JDF2 魔数的旧备份） */
    private fun importLegacy(raw: ByteArray, passphrase: String): BackupImportResult {
        if (raw.size < MIN_BYTES_LEGACY) {
            return BackupImportResult.Error(BackupError.CORRUPT_FORMAT, "旧版备份数据长度不足或已截断")
        }

        var keyBytes: ByteArray? = null
        var decryptedBytes: ByteArray? = null
        return try {
            val iv = ByteArray(IV_LENGTH)
            val cipherText = ByteArray(raw.size - IV_LENGTH)
            System.arraycopy(raw, 0, iv, 0, IV_LENGTH)
            System.arraycopy(raw, IV_LENGTH, cipherText, 0, cipherText.size)

            keyBytes = MessageDigest.getInstance("SHA-256")
                .digest(passphrase.toByteArray(StandardCharsets.UTF_8))
            val secretKey = SecretKeySpec(keyBytes, "AES")

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
            decryptedBytes = cipher.doFinal(cipherText)
            val decryptedJson = String(decryptedBytes, StandardCharsets.UTF_8)
            validateAndSanitize(decryptedJson)
        } catch (_: AEADBadTagException) {
            BackupImportResult.Error(BackupError.WRONG_PASSPHRASE_OR_TAMPERED, "备份口令错误或备份数据已被篡改")
        } catch (e: Exception) {
            BackupImportResult.Error(BackupError.CORRUPT_FORMAT, e.message ?: "旧版备份解密失败")
        } finally {
            keyBytes?.fill(0)
            decryptedBytes?.fill(0)
        }
    }

    private fun validateAndSanitize(decryptedJson: String): BackupImportResult {
        if (decryptedJson.isBlank()) {
            return BackupImportResult.Error(BackupError.EMPTY_PAYLOAD, "备份载荷为空")
        }

        val rawPayload = try {
            gson.fromJson(decryptedJson, BackupPayload::class.java)
        } catch (e: Exception) {
            return BackupImportResult.Error(BackupError.CORRUPT_FORMAT, "备份 JSON 格式损坏: ${e.javaClass.simpleName}")
        } ?: return BackupImportResult.Error(BackupError.EMPTY_PAYLOAD, "备份载荷为空")

        @Suppress("USELESS_ELVIS")
        val workspaces = (rawPayload.workspaces ?: emptyList())
            .filterNotNull()
            .map { it.normalize() }

        @Suppress("USELESS_ELVIS")
        val tags = (rawPayload.tags ?: emptyList())
            .filterNotNull()
            .map { it.normalize() }

        @Suppress("USELESS_ELVIS")
        val rawTokens = (rawPayload.tokens ?: emptyList()).filterNotNull()

        var skippedCorruptTokens = 0
        val validTokens = ArrayList<AuthToken>(rawTokens.size)
        for (token in rawTokens) {
            val normalized = token.normalize()
            if (normalized.secretInvalid || !isValidBase32Secret(normalized.secret)) {
                skippedCorruptTokens++
            } else {
                validTokens.add(normalized.copy(secretInvalid = false))
            }
        }

        if (workspaces.isEmpty() && tags.isEmpty() && validTokens.isEmpty() && skippedCorruptTokens == 0) {
            return BackupImportResult.Error(BackupError.EMPTY_PAYLOAD, "备份中没有任何有效数据")
        }

        val sanitized = BackupPayload(
            version = if (rawPayload.version > 0) rawPayload.version else VERSION.toInt(),
            schemaVersion = CURRENT_VAULT_SCHEMA_VERSION,
            timestamp = if (rawPayload.timestamp > 0L) rawPayload.timestamp else System.currentTimeMillis(),
            workspaces = workspaces,
            tags = tags,
            tokens = validTokens
        )
        return BackupImportResult.Ok(
            payload = sanitized,
            skippedCorruptTokens = skippedCorruptTokens
        )
    }
}
