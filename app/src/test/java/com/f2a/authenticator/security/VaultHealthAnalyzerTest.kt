package com.f2a.authenticator.security

import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.AutoLockTimeout
import com.f2a.authenticator.data.model.VaultPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultHealthAnalyzerTest {

    private val dayMs = 24L * 60L * 60L * 1000L

    @Test
    fun analyze_healthyVault_returnsHighScoreAndNoWarnings() {
        val now = 1_700_000_000_000L
        val tokens = listOf(
            AuthToken(id = "1", issuer = "GitHub", accountName = "a", secret = "JBSWY3DPEHPK3PXP"),
            AuthToken(id = "2", issuer = "AWS", accountName = "b", secret = "GEZDGNBVGY3TQOJQ")
        )
        val prefs = VaultPreferences(
            autoLockTimeout = AutoLockTimeout.SECONDS_30,
            privacyMaskEnabled = true,
            lastBackupAtMillis = now - 5 * dayMs,
            lastBackupTokenCount = 2
        )

        val report = VaultHealthAnalyzer.analyze(
            tokens = tokens,
            preferences = prefs,
            isDuressConfigured = true,
            isBiometricEnabled = true,
            nowMs = now,
            isFlagSecureEnabled = true,
            clipboardClearSeconds = 45
        )

        assertEquals(100, report.score)
        assertEquals(0, report.corruptedCount)
        assertEquals(0, report.duplicateCount)
        assertEquals(0, report.weakSecretCount)
        assertFalse(report.backupOverdue)
        assertEquals(5, report.daysSinceLastBackup)
        assertTrue(report.items.none { it.severity != HealthSeverity.OK })
    }

    @Test
    fun analyze_detectsAllRiskCategories_andIgnoresTrashedTokens() {
        val now = 1_700_000_000_000L
        val tokens = listOf(
            AuthToken(id = "1", issuer = "A", accountName = "1", secret = "JBSWY3DPEHPK3PXP"),
            AuthToken(id = "2", issuer = "B", accountName = "2", secret = "jbswy3dp-ehpk3pxp"), // 重复密钥
            AuthToken(id = "3", issuer = "C", accountName = "3", secret = "ABCDEFGH"), // 8 chars = 5 bytes < 10 bytes
            AuthToken(id = "4", issuer = "D", accountName = "4", secret = "", secretInvalid = true),
            AuthToken(id = "5", issuer = "Trash", accountName = "5", secret = "ABCDEFGH", secretInvalid = true, deletedAt = now - dayMs)
        )
        val prefs = VaultPreferences(
            autoLockTimeout = AutoLockTimeout.NEVER,
            privacyMaskEnabled = false,
            lastBackupAtMillis = null,
            lastBackupTokenCount = 0
        )

        val report = VaultHealthAnalyzer.analyze(
            tokens = tokens,
            preferences = prefs,
            isDuressConfigured = false,
            isBiometricEnabled = false,
            nowMs = now,
            isFlagSecureEnabled = false,
            clipboardClearSeconds = 0
        )

        assertEquals(1, report.corruptedCount)
        assertEquals(1, report.duplicateCount)
        assertEquals(1, report.weakSecretCount)
        assertTrue(report.backupOverdue)
        assertNull(report.daysSinceLastBackup)
        assertTrue(report.score < 30)
        assertEquals(HealthSeverity.CRITICAL, report.items.first().severity)
    }

    @Test
    fun analyze_backupOverdueAfter30Days() {
        val now = 1_700_000_000_000L
        val tokens = listOf(
            AuthToken(id = "1", issuer = "GitHub", accountName = "a", secret = "JBSWY3DPEHPK3PXP")
        )
        val prefs = VaultPreferences(
            autoLockTimeout = AutoLockTimeout.IMMEDIATE,
            lastBackupAtMillis = now - 31 * dayMs,
            lastBackupTokenCount = 1
        )

        val report = VaultHealthAnalyzer.analyze(
            tokens = tokens,
            preferences = prefs,
            isDuressConfigured = true,
            isBiometricEnabled = false,
            nowMs = now
        )

        assertTrue(report.backupOverdue)
        assertEquals(31, report.daysSinceLastBackup)
        assertTrue(report.items.any { it.id == "backup_status" && it.severity == HealthSeverity.WARNING })
    }
}
