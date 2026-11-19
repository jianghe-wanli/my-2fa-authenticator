package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.TokenType
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * 纯 Kotlin 标准 Key URI 与二维码内容解析器（零 Android 框架依赖）
 * 1. 标准协议：otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
 * 2. 支持 otpauth://steam/... 及 issuer=Steam&digits=5 自动识别为 5 位 Steam 令牌
 * 3. 智能提取环境：仅识别约定白名单末尾标记（如 [Prod]/[Dev]/[Test]/[Stage]），避免误伤账号合法括号
 */
object OtpUriParser {

    sealed class OtpParseResult {
        data class Ok(val token: AuthToken) : OtpParseResult()
        data class Error(val reason: String) : OtpParseResult()
    }

    private const val BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private const val MAX_URI_LENGTH = 8192

    // 仅识别末尾的约定白名单标记
    private val ENV_TRAILING_REGEX =
        Regex("""\s*[\[(](Prod|Dev|Test|Stage|生产|开发|测试|预发|灰度)[\])]\s*$""", RegexOption.IGNORE_CASE)

    fun normalizeBase32(s: String): String =
        s.trim()
            .replace("-", "")
            .replace(" ", "")
            .replace("\n", "")
            .replace("\r", "")
            .replace("=", "")
            .uppercase(Locale.US)

    fun isStrictBase32Secret(s: String): Boolean {
        val c = normalizeBase32(s)
        return c.length >= 8 && c.all { it in BASE32_CHARS } && OtpEngine.decodeBase32(c).isNotEmpty()
    }

    private fun safeDigits(d: Int?): Int = when (d) {
        8 -> 8
        6 -> 6
        else -> 6
    }

    private fun safePeriod(p: Int?): Int {
        val v = p ?: 30
        return if (v in 10..300) v else 30
    }

    private fun normalizeAlgorithm(raw: String?): String? {
        if (raw.isNullOrBlank()) return "SHA1"
        return when (raw.trim().uppercase(Locale.US)) {
            "SHA1", "SHA-1", "HMACSHA1" -> "SHA1"
            "SHA256", "SHA-256", "HMACSHA256" -> "SHA256"
            "SHA512", "SHA-512", "HMACSHA512" -> "SHA512"
            else -> null
        }
    }

    fun parse(uriString: String): AuthToken? =
        (parseDetailed(uriString) as? OtpParseResult.Ok)?.token

    fun parseDetailed(uriString: String): OtpParseResult {
        val cleanUri = uriString.trim()
        if (cleanUri.isEmpty()) {
            return OtpParseResult.Error("输入内容为空")
        }
        if (cleanUri.length > MAX_URI_LENGTH) {
            return OtpParseResult.Error("输入内容过长（超过 $MAX_URI_LENGTH 字符上限）")
        }

        if (cleanUri.startsWith("otpauth-migration://", ignoreCase = true)) {
            return OtpParseResult.Error("检测到 Google 迁移链接，请使用迁移导入")
        }

        if (!cleanUri.startsWith("otpauth://", ignoreCase = true)) {
            // 容错：有些二维码或输入只有纯 Base32 密钥（严格校验字符集与最小长度）
            return if (isStrictBase32Secret(cleanUri)) {
                OtpParseResult.Ok(
                    AuthToken(
                        issuer = "自定义凭据",
                        accountName = "默认账号",
                        secret = normalizeBase32(cleanUri)
                    )
                )
            } else {
                OtpParseResult.Error("无效的 OTP 链接或 Base32 密钥")
            }
        }

        if (cleanUri.contains('\n') || cleanUri.contains('\r')) {
            return OtpParseResult.Error("检测到多行内容，请改用批量文本导入")
        }

        return try {
            val withoutScheme = cleanUri.substring("otpauth://".length)
            val withoutFragment = withoutScheme.substringBefore('#')
            val qIdx = withoutFragment.indexOf('?')
            val authorityAndPath = if (qIdx >= 0) withoutFragment.substring(0, qIdx) else withoutFragment
            val rawQuery = if (qIdx >= 0) withoutFragment.substring(qIdx + 1) else ""

            val slashIdx = authorityAndPath.indexOf('/')
            val typeStr = (if (slashIdx >= 0) authorityAndPath.substring(0, slashIdx) else authorityAndPath)
                .trim()
                .lowercase(Locale.US)
            if (typeStr != "totp" && typeStr != "hotp" && typeStr != "steam") {
                return OtpParseResult.Error("不支持的 OTP 类型: $typeStr")
            }

            val rawPath = if (slashIdx >= 0) authorityAndPath.substring(slashIdx + 1) else ""
            val decodedPath = percentDecodePreservingPlus(rawPath).trim()

            val query = parseQueryParams(rawQuery)
            val rawSecret = query["secret"]
            if (rawSecret.isNullOrBlank()) {
                return OtpParseResult.Error("缺少 secret 参数")
            }
            if (!isStrictBase32Secret(rawSecret)) {
                return OtpParseResult.Error("secret 不是合法的 Base32 密钥")
            }
            val secret = normalizeBase32(rawSecret)

            val algorithm = normalizeAlgorithm(query["algorithm"])
                ?: return OtpParseResult.Error("不支持的哈希算法: ${query["algorithm"]}")

            val issuerParam = query["issuer"]?.trim()
            var issuerFromPath = ""
            var accountName = decodedPath
            if (!issuerParam.isNullOrBlank() &&
                decodedPath.startsWith("$issuerParam:", ignoreCase = true)
            ) {
                issuerFromPath = decodedPath.substring(0, issuerParam.length).trim()
                accountName = decodedPath.substring(issuerParam.length + 1).trim()
            } else if (decodedPath.contains(":")) {
                val parts = decodedPath.split(":", limit = 2)
                issuerFromPath = parts[0].trim()
                accountName = parts[1].trim()
            }

            val issuer = when {
                !issuerParam.isNullOrBlank() -> issuerParam
                issuerFromPath.isNotBlank() -> issuerFromPath
                else -> "未知平台"
            }

            val rawDigits = query["digits"]?.trim()?.toIntOrNull()
            val isSteam = typeStr == "steam" ||
                (issuer.equals("Steam", ignoreCase = true) && rawDigits == 5)
            val type = when {
                isSteam -> TokenType.STEAM
                typeStr == "hotp" -> TokenType.HOTP
                else -> TokenType.TOTP
            }

            val digits = if (type == TokenType.STEAM) 5 else safeDigits(rawDigits)
            val period = safePeriod(query["period"]?.trim()?.toIntOrNull())
            val counter = (query["counter"]?.trim()?.toLongOrNull() ?: 0L).coerceAtLeast(0L)

            // 智能识别环境标签：仅识别末尾白名单标记
            var detectedEnv = ""
            val match = ENV_TRAILING_REGEX.find(accountName)
            if (match != null) {
                detectedEnv = match.groupValues[1]
                accountName = accountName.replace(match.value, "").trim()
            }
            val finalAccountName = accountName.ifBlank { "默认账号" }

            OtpParseResult.Ok(
                AuthToken(
                    issuer = issuer,
                    accountName = finalAccountName,
                    tenantEnv = detectedEnv,
                    secret = secret,
                    algorithm = algorithm,
                    digits = digits,
                    period = period,
                    counter = counter,
                    type = type
                )
            )
        } catch (e: Exception) {
            OtpParseResult.Error("OTP 链接解析失败: ${e.message ?: "格式错误"}")
        }
    }

    /**
     * 将有效的本地凭据编码为标准 percent-encoded `otpauth://` URI（损坏或空密钥返回 null）。
     */
    fun buildOtpAuthUri(token: AuthToken): String? {
        if (token.secretInvalid || token.secret.isBlank()) return null
        val cleanSecret = normalizeBase32(token.secret)
        if (!isStrictBase32Secret(cleanSecret)) return null

        val typeStr = when (token.type) {
            TokenType.HOTP -> "hotp"
            TokenType.STEAM -> "steam"
            TokenType.TOTP -> "totp"
        }
        val issuer = token.issuer.trim().ifBlank { "未知平台" }
        val account = token.accountName.trim().ifBlank { "默认账号" }
        val label = if (token.tenantEnv.isNotBlank()) {
            "$issuer:$account [${token.tenantEnv.trim()}]"
        } else {
            "$issuer:$account"
        }

        val sb = StringBuilder()
        sb.append("otpauth://").append(typeStr).append('/').append(percentEncode(label))
        sb.append("?secret=").append(cleanSecret)
        sb.append("&issuer=").append(percentEncode(issuer))
        sb.append("&algorithm=").append(token.algorithm.uppercase(Locale.US))
        sb.append("&digits=").append(if (token.type == TokenType.STEAM) 5 else safeDigits(token.digits))
        if (token.type == TokenType.HOTP) {
            sb.append("&counter=").append(token.counter.coerceAtLeast(0L))
        } else {
            sb.append("&period=").append(if (token.type == TokenType.STEAM) 30 else safePeriod(token.period))
        }
        return sb.toString()
    }

    internal fun parseQueryParams(rawQuery: String): Map<String, String> {
        if (rawQuery.isBlank()) return emptyMap()
        val map = LinkedHashMap<String, String>()
        for (pair in rawQuery.split('&')) {
            if (pair.isEmpty()) continue
            val eqIdx = pair.indexOf('=')
            val rawKey = if (eqIdx >= 0) pair.substring(0, eqIdx) else pair
            val rawVal = if (eqIdx >= 0) pair.substring(eqIdx + 1) else ""
            val key = percentDecodePreservingPlus(rawKey).trim().lowercase(Locale.US)
            val value = percentDecodePreservingPlus(rawVal)
            if (key.isNotEmpty() && !map.containsKey(key)) {
                map[key] = value
            }
        }
        return map
    }

    /**
     * 仅解码 %XX UTF-8 序列，严格保留 '+' 原义（避免邮箱 user+tag@example.com 被误转为空格）。
     */
    internal fun percentDecodePreservingPlus(input: String): String {
        if (!input.contains('%')) return input
        val out = ByteArrayOutputStream(input.length)
        var i = 0
        while (i < input.length) {
            val ch = input[i]
            if (ch == '%' && i + 2 < input.length) {
                val hi = Character.digit(input[i + 1], 16)
                val lo = Character.digit(input[i + 2], 16)
                if (hi >= 0 && lo >= 0) {
                    out.write((hi shl 4) or lo)
                    i += 3
                    continue
                }
            }
            val bytes = ch.toString().toByteArray(StandardCharsets.UTF_8)
            out.write(bytes)
            i++
        }
        return String(out.toByteArray(), StandardCharsets.UTF_8)
    }

    private fun percentEncode(input: String): String {
        val bytes = input.toByteArray(StandardCharsets.UTF_8)
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            val isUnreserved = (c in 'A'.code..'Z'.code) ||
                (c in 'a'.code..'z'.code) ||
                (c in '0'.code..'9'.code) ||
                c == '-'.code || c == '_'.code || c == '.'.code || c == '~'.code
            if (isUnreserved) {
                out.append(c.toChar())
            } else {
                out.append('%')
                out.append(HEX_DIGITS[(c ushr 4) and 0x0F])
                out.append(HEX_DIGITS[c and 0x0F])
            }
        }
        return out.toString()
    }

    private const val HEX_DIGITS = "0123456789ABCDEF"
}
