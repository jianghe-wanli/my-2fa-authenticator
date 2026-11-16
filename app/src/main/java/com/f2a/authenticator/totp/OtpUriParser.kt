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

    // 仅识别末尾的约定白名单标记
    private val ENV_TRAILING_REGEX =
        Regex("""\s*[\[(](Prod|Dev|Test|Stage|生产|开发|测试|预发|灰度)[\])]\s*$""", RegexOption.IGNORE_CASE)

    private fun normalizeBase32Secret(s: String): String =
        s.trim()
            .replace("-", "")
            .replace(" ", "")
            .replace("\n", "")
            .replace("\r", "")
            .replace("=", "")
            .uppercase(Locale.US)

    private fun isStrictBase32(s: String): Boolean {
        val c = normalizeBase32Secret(s)
        return c.length >= 8 && c.all { it in BASE32_CHARS } && OtpEngine.decodeBase32(c).isNotEmpty()
    }

    private fun safeDigits(d: Int?): Int = when (d) {
        8 -> 8
        6 -> 6
        else -> 6
    }

    private fun safePeriod(p: Int?): Int {
        val v = p ?: 30
        return if (v in 15..120) v else 30
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

        if (cleanUri.startsWith("otpauth-migration://", ignoreCase = true)) {
            return OtpParseResult.Error("检测到 Google 迁移链接，请使用迁移导入")
        }

        if (!cleanUri.startsWith("otpauth://", ignoreCase = true)) {
            // 容错：有些二维码或输入只有纯 Base32 密钥（严格校验字符集）
            return if (isStrictBase32(cleanUri)) {
                OtpParseResult.Ok(
                    AuthToken(
                        issuer = "自定义凭据",
                        accountName = "默认账号",
                        secret = normalizeBase32Secret(cleanUri)
                    )
                )
            } else {
                OtpParseResult.Error("无效的 OTP 链接或 Base32 密钥")
            }
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

            var issuerFromPath = ""
            var accountName = decodedPath
            if (decodedPath.contains(":")) {
                val parts = decodedPath.split(":", limit = 2)
                issuerFromPath = parts[0].trim()
                accountName = parts[1].trim()
            }

            val query = parseQueryParams(rawQuery)
            val rawSecret = query["secret"]
            if (rawSecret.isNullOrBlank()) {
                return OtpParseResult.Error("缺少 secret 参数")
            }
            if (!isStrictBase32(rawSecret)) {
                return OtpParseResult.Error("secret 不是合法的 Base32 密钥")
            }
            val secret = normalizeBase32Secret(rawSecret)

            val algorithm = normalizeAlgorithm(query["algorithm"])
                ?: return OtpParseResult.Error("不支持的哈希算法: ${query["algorithm"]}")

            val issuerParam = query["issuer"]?.trim()
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
}
