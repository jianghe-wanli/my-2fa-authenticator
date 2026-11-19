package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.data.model.Workspace
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.util.Locale

data class ExternalImportResult(
    val tokens: List<AuthToken>,
    val skippedCount: Int,
    val formatName: String,
    val warnings: List<String> = emptyList()
)

/**
 * 外部主流 2FA 生态文本与未加密 JSON 迁移导入解析器（纯 Kotlin，支持 JVM 单测）：
 * 1. 多行 `otpauth://` / `otpauth-migration://` 文本（兼容 Ente Auth / FreeOTP+ / Authenticator Pro / 2FAS 明文）
 * 2. Aegis Authenticator 未加密 JSON (`db.entries`)
 * 3. 2FAS Auth 未加密 JSON (`services`)
 * 4. Bitwarden 未加密 JSON (`items[].login.totp`)
 */
object ExternalImportParser {

    private const val MAX_INPUT_CHARS = 2 * 1024 * 1024

    fun parse(
        rawInput: String,
        defaultWorkspaceId: String,
        existingWorkspaces: List<Workspace> = emptyList()
    ): ExternalImportResult {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            return ExternalImportResult(
                tokens = emptyList(),
                skippedCount = 0,
                formatName = "空输入",
                warnings = listOf("输入内容为空")
            )
        }
        if (trimmed.length > MAX_INPUT_CHARS) {
            return ExternalImportResult(
                tokens = emptyList(),
                skippedCount = 0,
                formatName = "超限输入",
                warnings = listOf("导入文本超过 2MB 体积上限，已拒绝解析")
            )
        }

        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return parseJsonImport(trimmed, defaultWorkspaceId, existingWorkspaces)
        }

        val lines = trimmed.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }

        if (lines.isEmpty()) {
            return ExternalImportResult(emptyList(), 0, "空输入", listOf("未检测到有效行"))
        }

        val hasOtpUriLines = lines.any {
            it.startsWith("otpauth://", ignoreCase = true) ||
                it.startsWith("otpauth-migration://", ignoreCase = true)
        }

        if (hasOtpUriLines) {
            return parseUriLines(lines, defaultWorkspaceId, existingWorkspaces)
        }

        // 单行裸 Base32 容错
        if (lines.size == 1) {
            return when (val single = OtpUriParser.parseDetailed(lines.first())) {
                is OtpUriParser.OtpParseResult.Ok -> ExternalImportResult(
                    tokens = listOf(enrichToken(single.token, defaultWorkspaceId, existingWorkspaces)),
                    skippedCount = 0,
                    formatName = "Base32 密钥"
                )
                is OtpUriParser.OtpParseResult.Error -> ExternalImportResult(
                    tokens = emptyList(),
                    skippedCount = 1,
                    formatName = "未知格式",
                    warnings = listOf(single.reason)
                )
            }
        }

        return ExternalImportResult(
            tokens = emptyList(),
            skippedCount = lines.size,
            formatName = "未知格式",
            warnings = listOf("未识别出 otpauth://、Google 迁移链接或受支持的 JSON 格式")
        )
    }

    private fun parseUriLines(
        lines: List<String>,
        defaultWorkspaceId: String,
        existingWorkspaces: List<Workspace>
    ): ExternalImportResult {
        val tokens = ArrayList<AuthToken>()
        val warnings = ArrayList<String>()
        var skipped = 0
        var hasMigration = false
        var hasStandard = false

        for ((idx, line) in lines.withIndex()) {
            if (GoogleMigrationDecoder.isGoogleMigrationUri(line)) {
                hasMigration = true
                val batch = GoogleMigrationDecoder.decodeBatch(line, defaultWorkspaceId)
                if (batch.tokens.isEmpty() && batch.skippedUnsupportedCount == 0) {
                    skipped++
                    warnings.add("第 ${idx + 1} 行 Google 迁移链接解析失败")
                } else {
                    skipped += batch.skippedUnsupportedCount
                    batch.tokens.forEach { t ->
                        tokens.add(enrichToken(t, defaultWorkspaceId, existingWorkspaces))
                    }
                    if (batch.skippedUnsupportedCount > 0) {
                        warnings.add("第 ${idx + 1} 行跳过 ${batch.skippedUnsupportedCount} 条不支持算法的迁移凭据")
                    }
                }
            } else if (line.startsWith("otpauth://", ignoreCase = true)) {
                hasStandard = true
                when (val res = OtpUriParser.parseDetailed(line)) {
                    is OtpUriParser.OtpParseResult.Ok -> {
                        tokens.add(enrichToken(res.token, defaultWorkspaceId, existingWorkspaces))
                    }
                    is OtpUriParser.OtpParseResult.Error -> {
                        skipped++
                        warnings.add("第 ${idx + 1} 行跳过：${res.reason}")
                    }
                }
            } else {
                skipped++
                warnings.add("第 ${idx + 1} 行非标准 OTP 链接，已跳过")
            }
        }

        val formatName = when {
            hasMigration && !hasStandard -> "Google 迁移链接"
            hasMigration && hasStandard -> "混合 OTP / Google 迁移链接"
            lines.size == 1 -> "otpauth:// 链接"
            else -> "多行 otpauth:// 批量文本"
        }

        return ExternalImportResult(
            tokens = tokens,
            skippedCount = skipped,
            formatName = formatName,
            warnings = warnings.distinct().take(5)
        )
    }

    private fun parseJsonImport(
        json: String,
        defaultWorkspaceId: String,
        existingWorkspaces: List<Workspace>
    ): ExternalImportResult {
        val root = try {
            JsonParser.parseString(json)
        } catch (e: Exception) {
            return ExternalImportResult(
                tokens = emptyList(),
                skippedCount = 0,
                formatName = "JSON 解析失败",
                warnings = listOf("JSON 语法损坏：${e.javaClass.simpleName}")
            )
        }

        if (!root.isJsonObject) {
            return ExternalImportResult(
                tokens = emptyList(),
                skippedCount = 0,
                formatName = "未知 JSON",
                warnings = listOf("仅支持 Aegis / 2FAS / Bitwarden 导出的 JSON 对象")
            )
        }
        val obj = root.asJsonObject

        // 1. Aegis JSON: { "version": 1, "db": { "entries": [...] } }
        val dbObj = obj.optObject("db")
        if (dbObj != null && dbObj.has("entries")) {
            return parseAegis(dbObj, defaultWorkspaceId, existingWorkspaces)
        }
        if (obj.has("entries") && obj.get("entries")?.isJsonArray == true) {
            return parseAegis(obj, defaultWorkspaceId, existingWorkspaces)
        }

        // 2. 2FAS JSON: { "services": [...] }
        if (obj.has("services") && obj.get("services")?.isJsonArray == true) {
            return parse2Fas(obj, defaultWorkspaceId, existingWorkspaces)
        }

        // 3. Bitwarden JSON: { "items": [...] }
        if (obj.has("items") && obj.get("items")?.isJsonArray == true) {
            return parseBitwarden(obj, defaultWorkspaceId, existingWorkspaces)
        }

        return ExternalImportResult(
            tokens = emptyList(),
            skippedCount = 0,
            formatName = "未识别 JSON",
            warnings = listOf("未能识别为 Aegis、2FAS 或 Bitwarden 未加密导出格式（不支持已加密库文件）")
        )
    }

    private fun parseAegis(
        dbObj: JsonObject,
        defaultWorkspaceId: String,
        existingWorkspaces: List<Workspace>
    ): ExternalImportResult {
        val entries = dbObj.getAsJsonArray("entries")
            ?: return ExternalImportResult(emptyList(), 0, "Aegis JSON", listOf("entries 列表为空"))

        val tokens = ArrayList<AuthToken>()
        val warnings = ArrayList<String>()
        var skipped = 0

        for (el in entries) {
            val entry = el.asObjOrNull()
            if (entry == null) {
                skipped++
                continue
            }
            val rawType = entry.optString("type").lowercase(Locale.US)
            val info = entry.optObject("info")
            if (info == null) {
                skipped++
                continue
            }
            val rawSecret = info.optString("secret")
            if (!OtpUriParser.isStrictBase32Secret(rawSecret)) {
                skipped++
                continue
            }

            val type = when (rawType) {
                "totp", "" -> TokenType.TOTP
                "hotp" -> TokenType.HOTP
                "steam" -> TokenType.STEAM
                else -> {
                    skipped++
                    warnings.add("Aegis 不支持的类型：$rawType")
                    continue
                }
            }

            val algo = normalizeAlgoOrNull(info.optString("algo").ifBlank { "SHA1" })
            if (algo == null) {
                skipped++
                warnings.add("跳过不支持的算法：${info.optString("algo")}")
                continue
            }

            val rawDigits = info.optInt("digits", if (type == TokenType.STEAM) 5 else 6)
            val digits = if (type == TokenType.STEAM) 5 else if (rawDigits == 8) 8 else 6
            val rawPeriod = info.optInt("period", 30)
            val period = if (type == TokenType.STEAM) 30 else if (rawPeriod in 10..300) rawPeriod else 30
            val counter = info.optLong("counter", 0L).coerceAtLeast(0L)

            val issuer = entry.optString("issuer").ifBlank { entry.optString("group") }.ifBlank { "未知平台" }
            val accountName = entry.optString("name").ifBlank { "默认账号" }
            val note = entry.optString("note")

            val token = AuthToken(
                workspaceId = defaultWorkspaceId,
                issuer = issuer,
                accountName = accountName,
                secret = OtpUriParser.normalizeBase32(rawSecret),
                algorithm = algo,
                digits = digits,
                period = period,
                counter = counter,
                type = type,
                note = note.ifBlank { "自 Aegis 导入" }
            )
            tokens.add(enrichToken(token, defaultWorkspaceId, existingWorkspaces))
        }

        return ExternalImportResult(
            tokens = tokens,
            skippedCount = skipped,
            formatName = "Aegis JSON",
            warnings = warnings.distinct().take(5)
        )
    }

    private fun parse2Fas(
        root: JsonObject,
        defaultWorkspaceId: String,
        existingWorkspaces: List<Workspace>
    ): ExternalImportResult {
        val services = root.getAsJsonArray("services")
            ?: return ExternalImportResult(emptyList(), 0, "2FAS JSON", listOf("services 列表为空"))

        val tokens = ArrayList<AuthToken>()
        val warnings = ArrayList<String>()
        var skipped = 0

        for (el in services) {
            val svc = el.asObjOrNull()
            if (svc == null) {
                skipped++
                continue
            }
            val otp = svc.optObject("otp") ?: svc
            val rawLink = otp.optString("link")
            if (rawLink.startsWith("otpauth://", ignoreCase = true)) {
                when (val parsed = OtpUriParser.parseDetailed(rawLink)) {
                    is OtpUriParser.OtpParseResult.Ok -> {
                        tokens.add(enrichToken(parsed.token, defaultWorkspaceId, existingWorkspaces))
                        continue
                    }
                    is OtpUriParser.OtpParseResult.Error -> Unit
                }
            }

            val rawSecret = svc.optString("secret").ifBlank { otp.optString("secret") }
            if (!OtpUriParser.isStrictBase32Secret(rawSecret)) {
                skipped++
                continue
            }

            val tokenTypeStr = otp.optString("tokenType").ifBlank { svc.optString("type") }.uppercase(Locale.US)
            val type = when (tokenTypeStr) {
                "HOTP" -> TokenType.HOTP
                "STEAM" -> TokenType.STEAM
                "TOTP", "" -> TokenType.TOTP
                else -> {
                    skipped++
                    warnings.add("2FAS 不支持的类型：$tokenTypeStr")
                    continue
                }
            }

            val algo = normalizeAlgoOrNull(otp.optString("algorithm").ifBlank { "SHA1" })
            if (algo == null) {
                skipped++
                warnings.add("跳过不支持的算法：${otp.optString("algorithm")}")
                continue
            }

            val rawDigits = otp.optInt("digits", if (type == TokenType.STEAM) 5 else 6)
            val digits = if (type == TokenType.STEAM) 5 else if (rawDigits == 8) 8 else 6
            val rawPeriod = otp.optInt("period", 30)
            val period = if (type == TokenType.STEAM) 30 else if (rawPeriod in 10..300) rawPeriod else 30
            val counter = otp.optLong("counter", 0L).coerceAtLeast(0L)

            val issuer = otp.optString("issuer").ifBlank { svc.optString("name") }.ifBlank { "未知平台" }
            val accountName = otp.optString("account").ifBlank { otp.optString("label") }.ifBlank { "默认账号" }

            val token = AuthToken(
                workspaceId = defaultWorkspaceId,
                issuer = issuer,
                accountName = accountName,
                secret = OtpUriParser.normalizeBase32(rawSecret),
                algorithm = algo,
                digits = digits,
                period = period,
                counter = counter,
                type = type,
                note = "自 2FAS 导入"
            )
            tokens.add(enrichToken(token, defaultWorkspaceId, existingWorkspaces))
        }

        return ExternalImportResult(
            tokens = tokens,
            skippedCount = skipped,
            formatName = "2FAS JSON",
            warnings = warnings.distinct().take(5)
        )
    }

    private fun parseBitwarden(
        root: JsonObject,
        defaultWorkspaceId: String,
        existingWorkspaces: List<Workspace>
    ): ExternalImportResult {
        val items = root.getAsJsonArray("items")
            ?: return ExternalImportResult(emptyList(), 0, "Bitwarden JSON", listOf("items 列表为空"))

        val tokens = ArrayList<AuthToken>()
        val warnings = ArrayList<String>()
        var skipped = 0

        for (el in items) {
            val item = el.asObjOrNull() ?: continue
            val login = item.optObject("login") ?: continue
            val rawTotp = login.optString("totp")
            if (rawTotp.isBlank()) continue

            val itemName = item.optString("name").ifBlank { "Bitwarden 凭据" }
            val username = login.optString("username").ifBlank { "默认账号" }

            if (rawTotp.startsWith("otpauth://", ignoreCase = true)) {
                when (val res = OtpUriParser.parseDetailed(rawTotp)) {
                    is OtpUriParser.OtpParseResult.Ok -> {
                        val patched = res.token.copy(
                            issuer = if (res.token.issuer == "未知平台") itemName else res.token.issuer,
                            accountName = if (res.token.accountName == "默认账号") username else res.token.accountName,
                            note = res.token.note.ifBlank { "自 Bitwarden 导入" }
                        )
                        tokens.add(enrichToken(patched, defaultWorkspaceId, existingWorkspaces))
                    }
                    is OtpUriParser.OtpParseResult.Error -> {
                        skipped++
                        warnings.add("$itemName：${res.reason}")
                    }
                }
            } else if (rawTotp.startsWith("steam://", ignoreCase = true)) {
                val rawSecret = rawTotp.removePrefix("steam://").removePrefix("STEAM://")
                if (OtpUriParser.isStrictBase32Secret(rawSecret)) {
                    tokens.add(
                        enrichToken(
                            AuthToken(
                                workspaceId = defaultWorkspaceId,
                                issuer = if (itemName.contains("steam", ignoreCase = true)) itemName else "Steam",
                                accountName = username,
                                secret = OtpUriParser.normalizeBase32(rawSecret),
                                digits = 5,
                                type = TokenType.STEAM,
                                note = "自 Bitwarden 导入"
                            ),
                            defaultWorkspaceId,
                            existingWorkspaces
                        )
                    )
                } else {
                    skipped++
                }
            } else if (OtpUriParser.isStrictBase32Secret(rawTotp)) {
                tokens.add(
                    enrichToken(
                        AuthToken(
                            workspaceId = defaultWorkspaceId,
                            issuer = itemName,
                            accountName = username,
                            secret = OtpUriParser.normalizeBase32(rawTotp),
                            note = "自 Bitwarden 导入"
                        ),
                        defaultWorkspaceId,
                        existingWorkspaces
                    )
                )
            } else {
                skipped++
            }
        }

        return ExternalImportResult(
            tokens = tokens,
            skippedCount = skipped,
            formatName = "Bitwarden JSON",
            warnings = warnings.distinct().take(5)
        )
    }

    private fun enrichToken(
        token: AuthToken,
        defaultWorkspaceId: String,
        existingWorkspaces: List<Workspace>
    ): AuthToken {
        val suggestion = WorkspaceInferenceEngine.infer(
            issuer = token.issuer,
            accountName = token.accountName,
            tenantEnv = token.tenantEnv,
            currentActiveWorkspaceId = defaultWorkspaceId,
            allWorkspaces = existingWorkspaces
        )
        return token.copy(
            workspaceId = suggestion.workspaceId,
            tagIds = (token.tagIds + suggestion.suggestedTagIds).distinct()
        )
    }

    private fun normalizeAlgoOrNull(raw: String): String? = when (raw.trim().uppercase(Locale.US)) {
        "", "SHA1", "SHA-1", "HMACSHA1" -> "SHA1"
        "SHA256", "SHA-256", "HMACSHA256" -> "SHA256"
        "SHA512", "SHA-512", "HMACSHA512" -> "SHA512"
        else -> null
    }

    private fun JsonElement?.asObjOrNull(): JsonObject? =
        if (this != null && isJsonObject) asJsonObject else null

    private fun JsonObject.optObject(key: String): JsonObject? {
        val el = get(key) ?: return null
        return if (el.isJsonObject) el.asJsonObject else null
    }

    private fun JsonObject.optString(key: String): String {
        val el = get(key) ?: return ""
        return if (el.isJsonPrimitive) el.asString.trim() else ""
    }

    private fun JsonObject.optInt(key: String, default: Int): Int {
        val el = get(key) ?: return default
        return try {
            if (el.isJsonPrimitive) el.asInt else default
        } catch (_: Exception) {
            default
        }
    }

    private fun JsonObject.optLong(key: String, default: Long): Long {
        val el = get(key) ?: return default
        return try {
            if (el.isJsonPrimitive) el.asLong else default
        } catch (_: Exception) {
            default
        }
    }
}
