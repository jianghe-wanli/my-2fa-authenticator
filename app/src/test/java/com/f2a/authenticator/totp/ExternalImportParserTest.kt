package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.TokenType
import com.f2a.authenticator.data.model.Workspace
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ExternalImportParserTest {

    private val workspaces = listOf(
        Workspace.DEFAULT_PERSONAL,
        Workspace.DEFAULT_WORK,
        Workspace.DEFAULT_DEVOPS
    )

    @Test
    fun parseMultilineOtpAuthUris_ignoresCommentsAndSkipsInvalidLines() {
        val input = """
            # Exported from Ente Auth
            otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub

            otpauth://hotp/VPN:bob?secret=GEZDGNBVGY3TQOJQ&issuer=VPN&counter=12
            otpauth://totp/Broken:x?secret=BAD!
            not-a-valid-line
        """.trimIndent()

        val result = ExternalImportParser.parse(input, "all", workspaces)
        assertEquals(2, result.tokens.size)
        assertEquals(2, result.skippedCount)
        assertEquals("多行 otpauth:// 批量文本", result.formatName)

        assertEquals("GitHub", result.tokens[0].issuer)
        assertEquals(TokenType.TOTP, result.tokens[0].type)
        assertEquals("VPN", result.tokens[1].issuer)
        assertEquals(TokenType.HOTP, result.tokens[1].type)
        assertEquals(12L, result.tokens[1].counter)
    }

    @Test
    fun parseAegisUnencryptedJson_extractsTotpHotpAndSteam() {
        val aegisJson = """
            {
              "version": 1,
              "db": {
                "version": 2,
                "entries": [
                  {
                    "type": "totp",
                    "name": "ops@company.com",
                    "issuer": "AWS",
                    "note": "Prod root",
                    "info": {
                      "secret": "JBSWY3DPEHPK3PXP",
                      "algo": "SHA256",
                      "digits": 8,
                      "period": 60
                    }
                  },
                  {
                    "type": "steam",
                    "name": "gamer1",
                    "issuer": "Steam",
                    "info": {
                      "secret": "GEZDGNBVGY3TQOJQ",
                      "algo": "SHA1",
                      "digits": 5,
                      "period": 30
                    }
                  },
                  {
                    "type": "totp",
                    "name": "bad",
                    "issuer": "Broken",
                    "info": {
                      "secret": "SHORT"
                    }
                  }
                ]
              }
            }
        """.trimIndent()

        val result = ExternalImportParser.parse(aegisJson, "all", workspaces)
        assertEquals("Aegis JSON", result.formatName)
        assertEquals(2, result.tokens.size)
        assertEquals(1, result.skippedCount)

        assertEquals("AWS", result.tokens[0].issuer)
        assertEquals("SHA256", result.tokens[0].algorithm)
        assertEquals(8, result.tokens[0].digits)
        assertEquals(60, result.tokens[0].period)
        assertEquals(Workspace.DEFAULT_DEVOPS.id, result.tokens[0].workspaceId)

        assertEquals(TokenType.STEAM, result.tokens[1].type)
        assertEquals(5, result.tokens[1].digits)
    }

    @Test
    fun parse2FasAndBitwardenJson_extractsValidEntries() {
        val twoFasJson = """
            {
              "services": [
                {
                  "name": "Cloudflare",
                  "secret": "JBSWY3DPEHPK3PXP",
                  "otp": {
                    "account": "dns@corp.io",
                    "issuer": "Cloudflare",
                    "digits": 6,
                    "period": 30,
                    "algorithm": "SHA1",
                    "tokenType": "TOTP"
                  }
                }
              ]
            }
        """.trimIndent()

        val res2Fas = ExternalImportParser.parse(twoFasJson, Workspace.DEFAULT_WORK.id, workspaces)
        assertEquals("2FAS JSON", res2Fas.formatName)
        assertEquals(1, res2Fas.tokens.size)
        assertEquals("Cloudflare", res2Fas.tokens.single().issuer)
        assertEquals(Workspace.DEFAULT_WORK.id, res2Fas.tokens.single().workspaceId)

        val bitwardenJson = """
            {
              "items": [
                {
                  "name": "Notion",
                  "login": {
                    "username": "lead@corp.io",
                    "totp": "otpauth://totp/Notion:lead@corp.io?secret=JBSWY3DPEHPK3PXP&issuer=Notion"
                  }
                },
                {
                  "name": "Steam",
                  "login": {
                    "username": "player",
                    "totp": "steam://GEZDGNBVGY3TQOJQ"
                  }
                },
                {
                  "name": "NoTotp",
                  "login": {
                    "username": "plain"
                  }
                }
              ]
            }
        """.trimIndent()

        val resBw = ExternalImportParser.parse(bitwardenJson, "all", workspaces)
        assertEquals("Bitwarden JSON", resBw.formatName)
        assertEquals(2, resBw.tokens.size)
        assertEquals(Workspace.DEFAULT_WORK.id, resBw.tokens[0].workspaceId)
        assertEquals(TokenType.STEAM, resBw.tokens[1].type)
    }

    @Test
    fun corruptJsonAndOversizedInput_safelyRejected() {
        val corrupt = ExternalImportParser.parse("{bad json", "all", workspaces)
        assertTrue(corrupt.tokens.isEmpty())
        assertTrue(corrupt.warnings.isNotEmpty())

        val huge = "a".repeat(2 * 1024 * 1024 + 10)
        val tooBig = ExternalImportParser.parse(huge, "all", workspaces)
        assertTrue(tooBig.tokens.isEmpty())
        assertEquals("超限输入", tooBig.formatName)
    }
}
