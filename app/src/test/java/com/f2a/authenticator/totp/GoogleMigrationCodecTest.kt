package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.TokenType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64

class GoogleMigrationCodecTest {

    @Test
    fun roundTrip_preservesIssuerWithColonAndFiltersSteamAndInvalid() {
        val validTotp = AuthToken(
            id = "t1",
            issuer = "Cloud:Corp",
            accountName = "ops@corp.com",
            tenantEnv = "Prod",
            secret = "JBSWY3DPEHPK3PXP",
            algorithm = "SHA256",
            digits = 8,
            period = 60,
            type = TokenType.TOTP
        )
        val validHotp = AuthToken(
            id = "t2",
            issuer = "VPN",
            accountName = "alice",
            secret = "GEZDGNBVGY3TQOJQ",
            digits = 6,
            type = TokenType.HOTP,
            counter = 7L
        )
        val steamToken = AuthToken(
            id = "t3",
            issuer = "Steam",
            accountName = "gamer",
            secret = "JBSWY3DPEHPK3PXP",
            digits = 5,
            type = TokenType.STEAM
        )
        val emptySecretToken = AuthToken(
            id = "t4",
            issuer = "Broken",
            accountName = "empty",
            secret = "",
            secretInvalid = false
        )
        val invalidFlagToken = AuthToken(
            id = "t5",
            issuer = "Corrupt",
            accountName = "bad",
            secret = "NOT_DECRYPTED_CIPHER",
            secretInvalid = true
        )

        val all = listOf(validTotp, validHotp, steamToken, emptySecretToken, invalidFlagToken)
        val plan = GoogleMigrationEncoder.buildExportPlan(all)

        assertEquals(2, plan.exportedCount)
        assertEquals(3, plan.skippedIncompatibleTokens.size)
        assertEquals(1, plan.degradedPeriodTokens.size)
        assertEquals("t1", plan.degradedPeriodTokens.first().id)
        assertEquals(1, plan.uris.size)

        val uris = GoogleMigrationEncoder.encodeToMigrationUris(all)
        assertEquals(1, uris.size)

        val decoded = GoogleMigrationDecoder.decode(uris.first(), "ws_target")
        assertEquals(2, decoded.size)

        val d1 = decoded[0]
        assertEquals("ws_target", d1.workspaceId)
        assertEquals("Cloud:Corp", d1.issuer)
        assertEquals("ops@corp.com", d1.accountName)
        assertEquals("Prod", d1.tenantEnv)
        assertEquals("JBSWY3DPEHPK3PXP", d1.secret)
        assertEquals("SHA256", d1.algorithm)
        assertEquals(8, d1.digits)
        assertEquals(TokenType.TOTP, d1.type)

        val d2 = decoded[1]
        assertEquals("VPN", d2.issuer)
        assertEquals("alice", d2.accountName)
        assertEquals(TokenType.HOTP, d2.type)
        assertEquals(7L, d2.counter)
    }

    @Test
    fun multiBatchExportAndDecodeBatch_preservesBatchMetadata() {
        val tokens = (1..8).map { i ->
            AuthToken(
                id = "id_$i",
                issuer = "Service$i",
                accountName = "user$i@test.com",
                secret = "JBSWY3DPEHPK3PXP"
            )
        }
        val uris = GoogleMigrationEncoder.encodeToMigrationUris(tokens)
        assertEquals(2, uris.size)

        val b0 = GoogleMigrationDecoder.decodeBatch(uris[0], "ws_1")
        val b1 = GoogleMigrationDecoder.decodeBatch(uris[1], "ws_1")

        assertEquals(6, b0.tokens.size)
        assertEquals(0, b0.batchIndex)
        assertEquals(2, b0.batchSize)

        assertEquals(2, b1.tokens.size)
        assertEquals(1, b1.batchIndex)
        assertEquals(2, b1.batchSize)
        assertEquals(b0.batchId, b1.batchId)
    }

    @Test
    fun urlSafeBase64_isDecodedProperly() {
        val uris = GoogleMigrationEncoder.encodeToMigrationUris(
            listOf(AuthToken(issuer = "GitHub", accountName = "octo", secret = "JBSWY3DPEHPK3PXP"))
        )
        val rawData = uris.first().substringAfter("data=")
        val standardB64 = java.net.URLDecoder.decode(rawData, StandardCharsets.UTF_8.name())
        val rawBytes = Base64.getDecoder().decode(standardB64)
        val urlSafeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawBytes)
        val urlSafeUri = "otpauth-migration://offline?data=$urlSafeB64"

        val decoded = GoogleMigrationDecoder.decode(urlSafeUri, "ws_url")
        assertEquals(1, decoded.size)
        assertEquals("GitHub", decoded.first().issuer)
        assertEquals("octo", decoded.first().accountName)
    }

    @Test
    fun maliciousProtobuf_overlongVarintAndInvalidWireType_safelyAborts() {
        // 构造 field 1 (wireType 2), 声明长度为 0x1_0000_0001 (绕过旧版 .toInt() 检查)
        val out = ByteArrayOutputStream()
        out.write((1 shl 3) or 2)
        // varint 0x100000001L: 0x81, 0x80, 0x80, 0x80, 0x10
        out.write(0x81)
        out.write(0x80)
        out.write(0x80)
        out.write(0x80)
        out.write(0x10)
        // 后跟非法 wireType=7 (tag = (2 shl 3) or 7 = 0x17)
        out.write(0x17)
        out.write(0xFF)

        val b64 = URLEncoder.encode(Base64.getEncoder().encodeToString(out.toByteArray()), "UTF-8")
        val batch = GoogleMigrationDecoder.decodeBatch("otpauth-migration://offline?data=$b64", "ws_bad")
        assertTrue(batch.tokens.isEmpty())

        // 直接以非法 wireType=7 开头
        val badWire = byteArrayOf(((9 shl 3) or 7).toByte(), 0x01, 0x02, 0x03)
        val badWireB64 = URLEncoder.encode(Base64.getEncoder().encodeToString(badWire), "UTF-8")
        val badBatch = GoogleMigrationDecoder.decodeBatch("otpauth-migration://offline?data=$badWireB64", "ws_bad")
        assertTrue(badBatch.tokens.isEmpty())
    }

    @Test
    fun md5AlgorithmRejected_sevenDigitsFlaggedIncompatible_andCaseInsensitiveIssuerPrefix() {
        // 1. 7 位凭据必须被拦截为不兼容（不得静默降级为 6 位）
        val sevenDigit = AuthToken(id = "d7", issuer = "Bank", accountName = "u", secret = "JBSWY3DPEHPK3PXP", digits = 7)
        val plan = GoogleMigrationEncoder.buildExportPlan(listOf(sevenDigit))
        assertEquals(0, plan.exportedCount)
        assertEquals(1, plan.skippedIncompatibleTokens.size)

        // 2. MD5 算法 (algoVal = 4) 应跳过并计入 skippedUnsupportedCount，而非静默按 SHA1 导入
        val paramOut = ByteArrayOutputStream()
        val secretBytes = OtpEngine.decodeBase32("JBSWY3DPEHPK3PXP")
        paramOut.write((1 shl 3) or 2); paramOut.write(secretBytes.size); paramOut.write(secretBytes)
        val nameBytes = "github:alice@x.com".toByteArray(StandardCharsets.UTF_8)
        paramOut.write((2 shl 3) or 2); paramOut.write(nameBytes.size); paramOut.write(nameBytes)
        val issuerBytes = "GitHub".toByteArray(StandardCharsets.UTF_8)
        paramOut.write((3 shl 3) or 2); paramOut.write(issuerBytes.size); paramOut.write(issuerBytes)
        paramOut.write((4 shl 3) or 0); paramOut.write(4) // MD5
        val md5Param = paramOut.toByteArray()

        // 另附一个合法 SHA1 + 大小写不同前缀 ("github:alice@x.com", issuer="GitHub")
        val validParamOut = ByteArrayOutputStream()
        validParamOut.write((1 shl 3) or 2); validParamOut.write(secretBytes.size); validParamOut.write(secretBytes)
        validParamOut.write((2 shl 3) or 2); validParamOut.write(nameBytes.size); validParamOut.write(nameBytes)
        validParamOut.write((3 shl 3) or 2); validParamOut.write(issuerBytes.size); validParamOut.write(issuerBytes)
        validParamOut.write((4 shl 3) or 0); validParamOut.write(1) // SHA1
        val validParam = validParamOut.toByteArray()

        val payloadOut = ByteArrayOutputStream()
        payloadOut.write((1 shl 3) or 2); payloadOut.write(md5Param.size); payloadOut.write(md5Param)
        payloadOut.write((1 shl 3) or 2); payloadOut.write(validParam.size); payloadOut.write(validParam)

        val b64 = URLEncoder.encode(Base64.getEncoder().encodeToString(payloadOut.toByteArray()), "UTF-8")
        val batch = GoogleMigrationDecoder.decodeBatch("otpauth-migration://offline/?data=$b64", "ws_1")
        assertEquals(1, batch.tokens.size)
        assertEquals(1, batch.skippedUnsupportedCount)
        assertEquals("GitHub", batch.tokens.single().issuer)
        assertEquals("alice@x.com", batch.tokens.single().accountName)
    }
}
