package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.TokenType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

class OtpUriParserTest {

    @Test
    fun parseStandardTotp_withPlusInEmailAndTrailingEnv_preservesPlusAndEnv() {
        val uri = "otpauth://totp/GitHub:user+work@example.com%20%5BProd%5D?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA-256&digits=8&period=60"
        val res = OtpUriParser.parseDetailed(uri)
        assertTrue(res is OtpUriParser.OtpParseResult.Ok)
        val token = (res as OtpUriParser.OtpParseResult.Ok).token
        assertEquals(TokenType.TOTP, token.type)
        assertEquals("GitHub", token.issuer)
        assertEquals("user+work@example.com", token.accountName)
        assertEquals("Prod", token.tenantEnv)
        assertEquals("JBSWY3DPEHPK3PXP", token.secret)
        assertEquals("SHA256", token.algorithm)
        assertEquals(8, token.digits)
        assertEquals(60, token.period)
    }

    @Test
    fun parseSteamUri_andSteamIssuerWith5Digits_mapToSteam() {
        val steamScheme = OtpUriParser.parseDetailed("otpauth://steam/Steam:player1?secret=JBSWY3DPEHPK3PXP&issuer=Steam")
        assertTrue(steamScheme is OtpUriParser.OtpParseResult.Ok)
        val t1 = (steamScheme as OtpUriParser.OtpParseResult.Ok).token
        assertEquals(TokenType.STEAM, t1.type)
        assertEquals(5, t1.digits)

        val steamTotp = OtpUriParser.parseDetailed("otpauth://totp/Steam:player2?secret=JBSWY3DPEHPK3PXP&issuer=Steam&digits=5")
        assertTrue(steamTotp is OtpUriParser.OtpParseResult.Ok)
        val t2 = (steamTotp as OtpUriParser.OtpParseResult.Ok).token
        assertEquals(TokenType.STEAM, t2.type)
        assertEquals(5, t2.digits)
    }

    @Test
    fun parseHotp_andEmptyAccountFallback() {
        val res = OtpUriParser.parseDetailed("otpauth://hotp/?secret=JBSWY3DPEHPK3PXP&issuer=CorpVPN&counter=42&algorithm=hmacsha512")
        assertTrue(res is OtpUriParser.OtpParseResult.Ok)
        val token = (res as OtpUriParser.OtpParseResult.Ok).token
        assertEquals(TokenType.HOTP, token.type)
        assertEquals(42L, token.counter)
        assertEquals("SHA512", token.algorithm)
        assertEquals("CorpVPN", token.issuer)
        assertEquals("默认账号", token.accountName)
    }

    @Test
    fun turkishLocale_lowercaseIInSecret_doesNotCorruptSecret() {
        val previous = Locale.getDefault()
        try {
            Locale.setDefault(Locale("tr", "TR"))
            val res = OtpUriParser.parseDetailed("otpauth://totp/Test:user@test.com?secret=iiiiiiii22222222&issuer=Test")
            assertTrue(res is OtpUriParser.OtpParseResult.Ok)
            val token = (res as OtpUriParser.OtpParseResult.Ok).token
            assertEquals("IIIIIIII22222222", token.secret)

            val plain = OtpUriParser.parse("iiiiiiii22222222")
            assertEquals("IIIIIIII22222222", plain?.secret)
        } finally {
            Locale.setDefault(previous)
        }
    }

    @Test
    fun invalidBase32AndUnsupportedAlgorithm_returnErrorAndNullParse() {
        val badSecret = OtpUriParser.parseDetailed("otpauth://totp/GitHub:a@b.com?secret=bad!123")
        assertTrue(badSecret is OtpUriParser.OtpParseResult.Error)
        assertNull(OtpUriParser.parse("otpauth://totp/GitHub:a@b.com?secret=bad!123"))

        val md5Algo = OtpUriParser.parseDetailed("otpauth://totp/GitHub:a@b.com?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")
        assertTrue(md5Algo is OtpUriParser.OtpParseResult.Error)

        val shortRaw = OtpUriParser.parseDetailed("ABCD")
        assertTrue(shortRaw is OtpUriParser.OtpParseResult.Error)
    }

    @Test
    fun outOfRangeDigitsPeriodCounter_safelyClamped() {
        val res = OtpUriParser.parseDetailed(
            "otpauth://hotp/Test:u?secret=JBSWY3DPEHPK3PXP&digits=99&period=5&counter=-10"
        )
        assertTrue(res is OtpUriParser.OtpParseResult.Ok)
        val token = (res as OtpUriParser.OtpParseResult.Ok).token
        assertEquals(6, token.digits)
        assertEquals(30, token.period)
        assertEquals(0L, token.counter)
    }
}
