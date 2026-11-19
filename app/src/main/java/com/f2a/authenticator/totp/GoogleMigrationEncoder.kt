package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.TokenType
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale

data class MigrationExportPlan(
    val uris: List<String>,
    val exportedCount: Int,
    val skippedIncompatibleTokens: List<AuthToken>,
    val degradedPeriodTokens: List<AuthToken>
)

/**
 * 纯 Kotlin 原生零依赖 Google Authenticator 迁移协议编码引擎
 * 将本地账号列表编码为 otpauth-migration://offline?data=...
 */
object GoogleMigrationEncoder {

    // 迁移 URI 较长，单包 6 个账号可确保二维码密度适中、被另一台手机稳定扫出
    const val MAX_TOKENS_PER_QR = 6

    /**
     * 返回无法无损导出到 Google Authenticator 的令牌
     * （密钥损坏 secretInvalid、Steam/5 位、非 6/8 位、空 secret）。
     */
    fun findIncompatibleTokens(tokens: List<AuthToken>): List<AuthToken> {
        return tokens.filter { t ->
            t.secretInvalid ||
                t.type == TokenType.STEAM ||
                t.digits !in setOf(6, 8) ||
                OtpEngine.decodeBase32(t.secret).isEmpty()
        }
    }

    /**
     * 可安全导出的令牌（排除 secretInvalid / Steam / 非法 digits / 空 secret）。
     * 严禁把 secretInvalid 令牌的密文占位当作种子编码进迁移 QR。
     */
    fun exportableTokens(tokens: List<AuthToken>): List<AuthToken> {
        val badIds = findIncompatibleTokens(tokens).map { it.id }.toHashSet()
        return tokens.filter { it.id !in badIds }
    }

    /**
     * 构建结构化迁移导出计划：同步输出分包 URI、实际导出数、不可导出的跳过列表、及 60s 等非 30s 周期降级提醒列表。
     */
    fun buildExportPlan(tokens: List<AuthToken>): MigrationExportPlan {
        val incompatible = findIncompatibleTokens(tokens)
        val badIds = incompatible.map { it.id }.toHashSet()
        val exportable = tokens.filter { it.id !in badIds }
        val degradedPeriod = exportable.filter { it.type == TokenType.TOTP && it.period != 30 }
        val uris = encodeFilteredToMigrationUris(exportable)
        return MigrationExportPlan(
            uris = uris,
            exportedCount = exportable.size,
            skippedIncompatibleTokens = incompatible,
            degradedPeriodTokens = degradedPeriod
        )
    }

    /**
     * 将 AuthToken 列表分包并编码为多个迁移 URI（强制仅编码 exportableTokens）
     */
    fun encodeToMigrationUris(tokens: List<AuthToken>): List<String> {
        val safe = exportableTokens(tokens)
        return encodeFilteredToMigrationUris(safe)
    }

    private fun encodeFilteredToMigrationUris(safe: List<AuthToken>): List<String> {
        if (safe.isEmpty()) return emptyList()

        val chunks = safe.chunked(MAX_TOKENS_PER_QR)
        val batchId = (System.currentTimeMillis() and 0xFFFF).toInt()

        return chunks.mapIndexed { index, chunk ->
            val payloadBytes = buildMigrationPayload(chunk, index, chunks.size, batchId)
            val base64Data = Base64.getEncoder().encodeToString(payloadBytes)
            val encodedData = URLEncoder.encode(base64Data, StandardCharsets.UTF_8.name())
            "otpauth-migration://offline?data=$encodedData"
        }
    }

    private fun buildMigrationPayload(
        tokens: List<AuthToken>,
        batchIndex: Int,
        batchSize: Int,
        batchId: Int
    ): ByteArray {
        val out = ByteArrayOutputStream()

        // 1. repeated OtpParameters otp_parameters = 1;
        for (token in tokens) {
            val paramBytes = buildOtpParameters(token)
            writeVarint(out, (1 shl 3) or 2) // field 1, wireType 2
            writeVarint(out, paramBytes.size.toLong())
            out.write(paramBytes)
        }

        // 2. int32 version = 2;
        writeVarint(out, (2 shl 3) or 0)
        writeVarint(out, 1L)

        // 3. int32 batch_size = 3;
        writeVarint(out, (3 shl 3) or 0)
        writeVarint(out, batchSize.toLong())

        // 4. int32 batch_index = 4;
        writeVarint(out, (4 shl 3) or 0)
        writeVarint(out, batchIndex.toLong())

        // 5. int32 batch_id = 5;
        writeVarint(out, (5 shl 3) or 0)
        writeVarint(out, batchId.toLong())

        return out.toByteArray()
    }

    private fun buildOtpParameters(token: AuthToken): ByteArray {
        val out = ByteArrayOutputStream()

        // 1. bytes secret = 1;
        val secretBytes = OtpEngine.decodeBase32(token.secret)
        if (secretBytes.isNotEmpty()) {
            writeVarint(out, (1 shl 3) or 2)
            writeVarint(out, secretBytes.size.toLong())
            out.write(secretBytes)
        }

        // 2. string name = 2; (Issuer:AccountName 或 带环境角标)
        val displayName = if (token.tenantEnv.isNotBlank()) {
            "${token.issuer}:${token.accountName} [${token.tenantEnv}]"
        } else {
            "${token.issuer}:${token.accountName}"
        }
        val nameBytes = displayName.toByteArray(StandardCharsets.UTF_8)
        writeVarint(out, (2 shl 3) or 2)
        writeVarint(out, nameBytes.size.toLong())
        out.write(nameBytes)

        // 3. string issuer = 3;
        val issuerBytes = token.issuer.toByteArray(StandardCharsets.UTF_8)
        writeVarint(out, (3 shl 3) or 2)
        writeVarint(out, issuerBytes.size.toLong())
        out.write(issuerBytes)

        // 4. Algorithm algorithm = 4; (1: SHA1, 2: SHA256, 3: SHA512)
        val algoVal = when (token.algorithm.uppercase(Locale.US)) {
            "SHA256" -> 2L
            "SHA512" -> 3L
            else -> 1L
        }
        writeVarint(out, (4 shl 3) or 0)
        writeVarint(out, algoVal)

        // 5. DigitCount digits = 5; (1: 6位, 2: 8位)
        val digitVal = if (token.digits == 8) 2L else 1L
        writeVarint(out, (5 shl 3) or 0)
        writeVarint(out, digitVal)

        // 6. OtpType type = 6; (1: HOTP, 2: TOTP)
        val typeVal = if (token.type == TokenType.HOTP) 1L else 2L
        writeVarint(out, (6 shl 3) or 0)
        writeVarint(out, typeVal)

        // 7. int64 counter = 7;
        if (token.type == TokenType.HOTP) {
            writeVarint(out, (7 shl 3) or 0)
            writeVarint(out, token.counter)
        }

        return out.toByteArray()
    }

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var v = value
        while (v and 0x7F.inv() != 0L) {
            out.write(((v and 0x7F) or 0x80).toInt())
            v = v ushr 7
        }
        out.write((v and 0x7F).toInt())
    }
}
