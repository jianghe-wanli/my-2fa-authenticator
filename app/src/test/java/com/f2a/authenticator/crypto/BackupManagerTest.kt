package com.f2a.authenticator.crypto

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.BackupPayload
import com.f2a.authenticator.data.model.CURRENT_VAULT_SCHEMA_VERSION
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.data.model.Workspace
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class BackupManagerTest {

    private fun samplePayload(): BackupPayload {
        val ws = Workspace.DEFAULT_PERSONAL
        val tag = Tag.TAG_MAIN
        val totp = AuthToken(
            id = "tok-1",
            workspaceId = ws.id,
            issuer = "GitHub",
            accountName = "alice@example.com",
            secret = "JBSWY3DPEHPK3PXP",
            algorithm = "SHA1",
            digits = 6,
            period = 30,
            type = TokenType.TOTP,
            tagIds = listOf(tag.id)
        )
        val steam = AuthToken(
            id = "tok-2",
            workspaceId = ws.id,
            issuer = "Steam",
            accountName = "gamer",
            secret = "JBSWY3DPEHPK3PXP",
            digits = 5,
            type = TokenType.STEAM
        )
        return BackupPayload(
            version = 2,
            schemaVersion = CURRENT_VAULT_SCHEMA_VERSION,
            workspaces = listOf(ws),
            tags = listOf(tag),
            tokens = listOf(totp, steam)
        )
    }

    private fun buildRawJdf2(
        json: String,
        passphrase: String,
        version: Byte = 2,
        iterations: Int = 10_000
    ): String {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, iterations, 256)
        val keyBytes = try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
        val key = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(json.toByteArray(StandardCharsets.UTF_8))

        val out = ByteArrayOutputStream()
        out.write("JDF2".toByteArray(StandardCharsets.US_ASCII))
        out.write(version.toInt())
        out.write(ByteBuffer.allocate(4).putInt(iterations).array())
        out.write(salt)
        out.write(iv)
        out.write(encrypted)
        return Base64.getEncoder().encodeToString(out.toByteArray())
    }

    @Test
    fun exportAndImportJdf2_roundTripSuccess() {
        val payload = samplePayload()
        val exportResult = BackupManager.exportEncryptedBackup(payload, "CorrectHorseBatteryStaple!")
        assertTrue(exportResult is BackupExportResult.Ok)
        val okExport = exportResult as BackupExportResult.Ok
        assertEquals(2, okExport.exportedCount)
        assertEquals(0, okExport.skippedInvalidCount)

        val raw = Base64.getDecoder().decode(okExport.encodedBase64)
        assertEquals("JDF2", String(raw, 0, 4, StandardCharsets.US_ASCII))
        assertEquals(2, raw[4].toInt())
        assertEquals(210_000, ByteBuffer.wrap(raw, 5, 4).int)

        val importResult = BackupManager.importEncryptedBackup(okExport.encodedBase64, "CorrectHorseBatteryStaple!")
        assertTrue(importResult is BackupImportResult.Ok)
        val okImport = importResult as BackupImportResult.Ok
        assertEquals(0, okImport.skippedCorruptTokens)
        assertEquals(2, okImport.payload.tokens.size)
        assertEquals("GitHub", okImport.payload.tokens[0].issuer)
        assertEquals(TokenType.STEAM, okImport.payload.tokens[1].type)
        assertEquals(5, okImport.payload.tokens[1].digits)
    }

    @Test
    fun export_filtersSecretInvalidAndSoftDeletedTokens() {
        val valid = AuthToken(id = "valid", issuer = "Google", accountName = "u1", secret = "JBSWY3DPEHPK3PXP")
        val invalid = AuthToken(id = "bad", issuer = "Broken", accountName = "u2", secret = "cipher", secretInvalid = true)
        val trashed = AuthToken(id = "trash", issuer = "Deleted", accountName = "u3", secret = "JBSWY3DPEHPK3PXP", deletedAt = 123456L)

        val payload = BackupPayload(
            workspaces = listOf(Workspace.DEFAULT_PERSONAL),
            tags = listOf(Tag.TAG_MAIN),
            tokens = listOf(valid, invalid, trashed)
        )

        val exportResult = BackupManager.exportEncryptedBackup(payload, "StrongPass#2026") as BackupExportResult.Ok
        assertEquals(1, exportResult.exportedCount)
        assertEquals(2, exportResult.skippedInvalidCount)

        val importResult = BackupManager.importEncryptedBackup(exportResult.encodedBase64, "StrongPass#2026") as BackupImportResult.Ok
        assertEquals(1, importResult.payload.tokens.size)
        assertEquals("valid", importResult.payload.tokens.single().id)
    }

    @Test
    fun import_legacyV1PayloadCompatible() {
        val json = """
            {
              "version": 1,
              "timestamp": 1700000000000,
              "workspaces": [{"id": "workspace_personal", "name": "个人生活"}],
              "tags": [],
              "tokens": [{"id": "t1", "issuer": "GitLab", "accountName": "dev", "secret": "JBSWY3DPEHPK3PXP"}]
            }
        """.trimIndent()
        val passphrase = "legacy-password"
        val keyBytes = MessageDigest.getInstance("SHA-256")
            .digest(passphrase.toByteArray(StandardCharsets.UTF_8))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"))
        val iv = cipher.iv
        val encrypted = cipher.doFinal(json.toByteArray(StandardCharsets.UTF_8))

        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)
        val legacyB64 = Base64.getEncoder().encodeToString(combined)

        val result = BackupManager.importEncryptedBackup(legacyB64, passphrase)
        assertTrue(result is BackupImportResult.Ok)
        val ok = result as BackupImportResult.Ok
        assertEquals(1, ok.payload.tokens.size)
        assertEquals("GitLab", ok.payload.tokens[0].issuer)
        assertEquals(0, ok.skippedCorruptTokens)
    }

    @Test
    fun import_jdf2WrongPassphrase_doesNotFallbackToLegacy() {
        val b64 = buildRawJdf2(
            json = """{"version":2,"workspaces":[],"tags":[],"tokens":[{"issuer":"A","accountName":"B","secret":"JBSWY3DPEHPK3PXP"}]}""",
            passphrase = "right-password",
            iterations = 10_000
        )

        val result = BackupManager.importEncryptedBackup(b64, "wrong-password")
        assertTrue(result is BackupImportResult.Error)
        assertEquals(BackupError.WRONG_PASSPHRASE_OR_TAMPERED, (result as BackupImportResult.Error).error)
    }

    @Test
    fun import_truncatedJdf2MissingTag_returnsCorruptFormat() {
        // JDF2 最小长度需 53 字节（37 头部 + 16 GCM Tag），此处仅 52 字节
        val truncated = ByteArray(52)
        "JDF2".toByteArray(StandardCharsets.US_ASCII).copyInto(truncated, 0)
        truncated[4] = 2
        ByteBuffer.allocate(4).putInt(210_000).array().copyInto(truncated, 5)
        val b64 = Base64.getEncoder().encodeToString(truncated)

        val result = BackupManager.importEncryptedBackup(b64, "any-pass")
        assertTrue(result is BackupImportResult.Error)
        assertEquals(BackupError.CORRUPT_FORMAT, (result as BackupImportResult.Error).error)
    }

    @Test
    fun import_truncatedLegacyMissingTag_returnsCorruptFormat() {
        // Legacy 最小长度需 28 字节（12 IV + 16 GCM Tag），此处仅 27 字节
        val truncated = ByteArray(27)
        val b64 = Base64.getEncoder().encodeToString(truncated)

        val result = BackupManager.importEncryptedBackup(b64, "any-pass")
        assertTrue(result is BackupImportResult.Error)
        assertEquals(BackupError.CORRUPT_FORMAT, (result as BackupImportResult.Error).error)
    }

    @Test
    fun import_iterationsOutOfBounds_rejectedImmediately() {
        val headerTooHigh = ByteArray(64)
        "JDF2".toByteArray(StandardCharsets.US_ASCII).copyInto(headerTooHigh, 0)
        headerTooHigh[4] = 2
        ByteBuffer.allocate(4).putInt(10_000_000).array().copyInto(headerTooHigh, 5)
        val highResult = BackupManager.importEncryptedBackup(
            Base64.getEncoder().encodeToString(headerTooHigh),
            "pass"
        )
        assertEquals(BackupError.INVALID_ITERATIONS, (highResult as BackupImportResult.Error).error)

        val headerTooLow = headerTooHigh.copyOf()
        ByteBuffer.allocate(4).putInt(9_999).array().copyInto(headerTooLow, 5)
        val lowResult = BackupManager.importEncryptedBackup(
            Base64.getEncoder().encodeToString(headerTooLow),
            "pass"
        )
        assertEquals(BackupError.INVALID_ITERATIONS, (lowResult as BackupImportResult.Error).error)
    }

    @Test
    fun import_unsupportedVersionAndInvalidBase64_rejected() {
        val unsupported = ByteArray(64)
        "JDF2".toByteArray(StandardCharsets.US_ASCII).copyInto(unsupported, 0)
        unsupported[4] = 9
        ByteBuffer.allocate(4).putInt(210_000).array().copyInto(unsupported, 5)

        val versionRes = BackupManager.importEncryptedBackup(
            Base64.getEncoder().encodeToString(unsupported),
            "pass"
        )
        assertEquals(BackupError.UNSUPPORTED_VERSION, (versionRes as BackupImportResult.Error).error)

        val badB64Res = BackupManager.importEncryptedBackup("not@valid!base64", "pass")
        assertEquals(BackupError.INVALID_BASE64, (badB64Res as BackupImportResult.Error).error)
    }

    @Test
    fun import_malformedJsonWithNullsAndInvalidSecrets_sanitizedWithoutNpe() {
        val malformedJson = """
            {
              "version": 2,
              "workspaces": null,
              "tags": null,
              "tokens": [
                {
                  "issuer": null,
                  "accountName": null,
                  "secret": "JBSWY3DPEHPK3PXP",
                  "period": 0,
                  "digits": 99
                },
                {
                  "issuer": "InvalidBase32",
                  "accountName": "bad",
                  "secret": "NOT_VALID_0189!"
                },
                {
                  "issuer": "EmptySecret",
                  "accountName": "empty",
                  "secret": ""
                }
              ]
            }
        """.trimIndent()

        val b64 = buildRawJdf2(malformedJson, "passphrase123", iterations = 10_000)
        val result = BackupManager.importEncryptedBackup(b64, "passphrase123")
        assertTrue(result is BackupImportResult.Ok)
        val ok = result as BackupImportResult.Ok
        assertEquals(2, ok.skippedCorruptTokens)
        assertEquals(1, ok.payload.tokens.size)
        val sanitizedToken = ok.payload.tokens.single()
        assertEquals("未知平台", sanitizedToken.issuer)
        assertEquals("默认账号", sanitizedToken.accountName)
        assertEquals(30, sanitizedToken.period)
        assertEquals(6, sanitizedToken.digits)
        assertTrue(ok.payload.workspaces.isEmpty())
        assertTrue(ok.payload.tags.isEmpty())
    }
}
