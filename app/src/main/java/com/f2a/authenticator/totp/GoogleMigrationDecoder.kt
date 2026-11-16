package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.TokenType
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlin.math.min

/**
 * 纯 Kotlin 原生零依赖 Google Authenticator 迁移协议二进制解包引擎
 * 格式：otpauth-migration://offline?data=CjEKC...
 */
object GoogleMigrationDecoder {

    data class MigrationBatch(
        val tokens: List<AuthToken>,
        val batchIndex: Int,
        val batchSize: Int,
        val batchId: Int,
        val version: Int
    )

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private const val MAX_FIELD_LEN = 4096
    private const val MAX_TOTAL_LEN = 65536

    private val ENV_TRAILING_REGEX =
        Regex("""\s*[\[(](Prod|Dev|Test|Stage|生产|开发|测试|预发|灰度)[\])]\s*$""", RegexOption.IGNORE_CASE)

    fun isGoogleMigrationUri(uriString: String): Boolean {
        return uriString.trim().startsWith("otpauth-migration://offline", ignoreCase = true)
    }

    /**
     * 解析 Google Authenticator 转移协议，解包出完整的账号列表
     */
    fun decode(migrationUri: String, targetWorkspaceId: String): List<AuthToken> {
        return decodeBatch(migrationUri, targetWorkspaceId).tokens
    }

    /**
     * 解析 Google Authenticator 转移协议及分包元数据（batchIndex/batchSize/batchId/version）
     */
    fun decodeBatch(migrationUri: String, targetWorkspaceId: String): MigrationBatch {
        val result = mutableListOf<AuthToken>()
        var version = 1
        var batchSize = 1
        var batchIndex = 0
        var batchId = 0
        var hasBatchSize = false

        try {
            val trimmedUri = migrationUri.trim()
            if (!isGoogleMigrationUri(trimmedUri)) {
                return MigrationBatch(emptyList(), 0, 0, 0, 1)
            }
            val qIdx = trimmedUri.indexOf('?')
            if (qIdx < 0) return MigrationBatch(emptyList(), 0, 0, 0, 1)
            val rawQuery = trimmedUri.substring(qIdx + 1).substringBefore('#')
            val query = OtpUriParser.parseQueryParams(rawQuery)
            val rawData = query["data"] ?: return MigrationBatch(emptyList(), 0, 0, 0, 1)

            val protoBytes = decodeBase64Flexible(rawData)
                ?: return MigrationBatch(emptyList(), 0, 0, 0, 1)
            if (protoBytes.size > MAX_TOTAL_LEN) {
                return MigrationBatch(emptyList(), 0, 0, 0, 1)
            }

            val stream = ByteArrayInputStream(protoBytes)

            // 解析外层 MigrationPayload
            while (stream.available() > 0) {
                val tag = readVarint(stream) ?: break
                val wireType = (tag and 0x07).toInt()
                val fieldNumber = (tag ushr 3).toInt()

                when (fieldNumber) {
                    1 -> {
                        if (wireType == 2) {
                            val declaredLong = readVarint(stream) ?: break
                            val maxAllowed = min(stream.available(), MAX_FIELD_LEN).toLong()
                            if (declaredLong <= 0L || declaredLong > maxAllowed) break
                            val declared = declaredLong.toInt()
                            val paramBytes = readExactBytes(stream, declared) ?: break
                            val token = parseOtpParameters(paramBytes, targetWorkspaceId)
                            if (token != null) {
                                result.add(token)
                            }
                        } else {
                            if (!skipField(stream, wireType)) break
                        }
                    }
                    2 -> { // int32 version
                        if (wireType == 0) {
                            val v = readVarint(stream) ?: break
                            version = v.toInt()
                        } else if (!skipField(stream, wireType)) break
                    }
                    3 -> { // int32 batch_size
                        if (wireType == 0) {
                            val v = readVarint(stream) ?: break
                            batchSize = v.toInt().coerceAtLeast(1)
                            hasBatchSize = true
                        } else if (!skipField(stream, wireType)) break
                    }
                    4 -> { // int32 batch_index
                        if (wireType == 0) {
                            val v = readVarint(stream) ?: break
                            batchIndex = v.toInt().coerceAtLeast(0)
                        } else if (!skipField(stream, wireType)) break
                    }
                    5 -> { // int32 batch_id
                        if (wireType == 0) {
                            val v = readVarint(stream) ?: break
                            batchId = v.toInt()
                        } else if (!skipField(stream, wireType)) break
                    }
                    else -> {
                        if (!skipField(stream, wireType)) break
                    }
                }
            }
        } catch (_: Throwable) {
            // 格式容错（含 OOM 等 Error，避免恶意输入直接打崩）
        }

        val finalBatchSize = if (result.isEmpty() && !hasBatchSize) 0 else batchSize
        return MigrationBatch(
            tokens = result,
            batchIndex = batchIndex,
            batchSize = finalBatchSize,
            batchId = batchId,
            version = version
        )
    }

    private fun decodeBase64Flexible(rawData: String): ByteArray? {
        val compact = rawData.trim()
            .replace("\r", "")
            .replace("\n", "")
            .replace(" ", "+")
        if (compact.isEmpty()) return null

        val isUrlSafe = compact.contains('-') || compact.contains('_')
        return try {
            if (isUrlSafe) {
                Base64.getUrlDecoder().decode(compact)
            } else {
                Base64.getDecoder().decode(compact)
            }
        } catch (_: Exception) {
            try {
                if (isUrlSafe) {
                    Base64.getDecoder().decode(compact.replace('-', '+').replace('_', '/'))
                } else {
                    Base64.getUrlDecoder().decode(compact)
                }
            } catch (_: Exception) {
                null
            }
        }
    }

    private fun parseOtpParameters(bytes: ByteArray, workspaceId: String): AuthToken? {
        val stream = ByteArrayInputStream(bytes)
        var secretBytes: ByteArray? = null
        var name = ""
        var issuer = ""
        var algorithm = "SHA1"
        var digits = 6
        var type = TokenType.TOTP
        var counter = 0L

        while (stream.available() > 0) {
            val tag = readVarint(stream) ?: break
            val wireType = (tag and 0x07).toInt()
            val fieldNumber = (tag ushr 3).toInt()

            when (fieldNumber) {
                1 -> { // secret (bytes)
                    if (wireType == 2) {
                        val lenLong = readVarint(stream) ?: break
                        val maxAllowed = min(stream.available(), MAX_FIELD_LEN).toLong()
                        if (lenLong <= 0L || lenLong > maxAllowed) break
                        val b = readExactBytes(stream, lenLong.toInt()) ?: break
                        secretBytes = b
                    } else if (!skipField(stream, wireType)) break
                }
                2 -> { // name (string)
                    if (wireType == 2) {
                        val lenLong = readVarint(stream) ?: break
                        val maxAllowed = min(stream.available(), MAX_FIELD_LEN).toLong()
                        if (lenLong < 0L || lenLong > maxAllowed) break
                        val b = readExactBytes(stream, lenLong.toInt()) ?: break
                        name = String(b, StandardCharsets.UTF_8)
                    } else if (!skipField(stream, wireType)) break
                }
                3 -> { // issuer (string)
                    if (wireType == 2) {
                        val lenLong = readVarint(stream) ?: break
                        val maxAllowed = min(stream.available(), MAX_FIELD_LEN).toLong()
                        if (lenLong < 0L || lenLong > maxAllowed) break
                        val b = readExactBytes(stream, lenLong.toInt()) ?: break
                        issuer = String(b, StandardCharsets.UTF_8)
                    } else if (!skipField(stream, wireType)) break
                }
                4 -> { // algorithm (enum)
                    if (wireType == 0) {
                        val algoVal = readVarint(stream) ?: break
                        algorithm = when (algoVal) {
                            2L -> "SHA256"
                            3L -> "SHA512"
                            else -> "SHA1"
                        }
                    } else if (!skipField(stream, wireType)) break
                }
                5 -> { // digits (enum)
                    if (wireType == 0) {
                        val digitVal = readVarint(stream) ?: break
                        digits = if (digitVal == 2L) 8 else 6
                    } else if (!skipField(stream, wireType)) break
                }
                6 -> { // type (enum)
                    if (wireType == 0) {
                        val typeVal = readVarint(stream) ?: break
                        type = if (typeVal == 1L) TokenType.HOTP else TokenType.TOTP
                    } else if (!skipField(stream, wireType)) break
                }
                7 -> { // counter (int64)
                    if (wireType == 0) {
                        counter = (readVarint(stream) ?: break).coerceAtLeast(0L)
                    } else if (!skipField(stream, wireType)) break
                }
                else -> {
                    if (!skipField(stream, wireType)) break
                }
            }
        }

        if (secretBytes == null || secretBytes.isEmpty()) return null

        // 将原始字节编码为 Base32 密钥字符串
        val base32Secret = encodeBase32(secretBytes)

        // 安全拆分 Issuer 与 AccountName：若已显式提供 issuer 字段，优先剥离 "$issuer:" 前缀避免 issuer 含冒号被误切
        var finalIssuer = issuer.trim()
        var finalAccount = name.trim()
        if (finalIssuer.isNotEmpty() && finalAccount.startsWith("$finalIssuer:")) {
            finalAccount = finalAccount.removePrefix("$finalIssuer:").trim()
        } else if (finalAccount.contains(":")) {
            val parts = finalAccount.split(":", limit = 2)
            if (finalIssuer.isEmpty()) finalIssuer = parts[0].trim()
            finalAccount = parts[1].trim()
        }
        if (finalIssuer.isEmpty()) finalIssuer = "Google迁移凭据"

        // 智能提取环境标签（仅末尾白名单）
        var detectedEnv = ""
        val match = ENV_TRAILING_REGEX.find(finalAccount)
        if (match != null) {
            detectedEnv = match.groupValues[1]
            finalAccount = finalAccount.replace(match.value, "").trim()
        }
        if (finalAccount.isEmpty()) finalAccount = "默认账号"

        return AuthToken(
            workspaceId = workspaceId,
            issuer = finalIssuer,
            accountName = finalAccount,
            tenantEnv = detectedEnv,
            secret = base32Secret,
            algorithm = algorithm,
            digits = digits,
            type = type,
            counter = counter,
            note = "自 Google Authenticator 迁移"
        )
    }

    private fun readExactBytes(stream: ByteArrayInputStream, len: Int): ByteArray? {
        if (len == 0) return ByteArray(0)
        val b = ByteArray(len)
        var readCount = 0
        while (readCount < len) {
            val c = stream.read(b, readCount, len - readCount)
            if (c < 0) return null
            readCount += c
        }
        return b
    }

    private fun readVarint(stream: ByteArrayInputStream): Long? {
        var result = 0L
        var shift = 0
        while (shift < 64) {
            val b = stream.read()
            if (b == -1) return null
            val chunk = (b and 0x7F).toLong()
            if (shift == 63 && chunk > 1L) return null
            result = result or (chunk shl shift)
            if ((b and 0x80) == 0) return result
            shift += 7
        }
        return null
    }

    private fun skipField(stream: ByteArrayInputStream, wireType: Int): Boolean {
        return when (wireType) {
            0 -> readVarint(stream) != null
            1 -> skipExact(stream, 8L)
            2 -> {
                val length = readVarint(stream) ?: return false
                if (length < 0L || length > min(stream.available(), MAX_FIELD_LEN).toLong()) {
                    return false
                }
                skipExact(stream, length)
            }
            5 -> skipExact(stream, 4L)
            else -> false
        }
    }

    private fun skipExact(stream: ByteArrayInputStream, count: Long): Boolean {
        if (count <= 0L) return count == 0L
        if (count > stream.available().toLong()) return false
        var remaining = count
        while (remaining > 0L) {
            val skipped = stream.skip(remaining)
            if (skipped <= 0L) return false
            remaining -= skipped
        }
        return true
    }

    private fun encodeBase32(data: ByteArray): String {
        val out = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                val index = (buffer shr (bitsLeft - 5)) and 31
                out.append(BASE32_ALPHABET[index])
                bitsLeft -= 5
            }
        }
        if (bitsLeft > 0) {
            val index = (buffer shl (5 - bitsLeft)) and 31
            out.append(BASE32_ALPHABET[index])
        }
        return out.toString()
    }
}
